#!/usr/bin/env python3
"""Reproduce node 94 reward-stage sort and bulk-tree evidence without execution."""
import argparse
import bisect
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import pathlib
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

BINARY = ROOT / "artifacts/node/94/hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

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
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 2000000
MUTANT_STEP_LIMIT = 60000
WORKERS = 4


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
        self.relative_map = None
        self.sections = sections(blob)
        # SHT_NOBITS sections have no file bytes, so they never resolve an address.
        self.mapped = sorted((s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]),
                             key=lambda s: s["address"])
        self.named = {s["name"]: s for s in self.sections}
        _, fdes = eh_frame_records(blob, self.sections)
        ends = {}
        self.fdes = {}
        for row in fdes:
            if row["start"] in ends:
                raise EvidenceError("duplicate FDE start")
            ends[row["start"]] = row["end"]
            self.fdes[row["start"]] = row
        self.fde_ends = ends
        self.starts = sorted(ends)

    def offset(self, va, size=1, executable=False):
        if va < 0 or size < 0:
            raise EvidenceError("negative address or size")
        found = [section for section in self.mapped
                 if (not executable or section["flags"] & 4)
                 and section["address"] <= va
                 and va + size <= section["address"] + section["size"]]
        if len(found) != 1:
            raise EvidenceError("address outside one file-backed section: %#x" % va)
        section = found[0]
        return va - section["address"] + section["offset"]

    def fde(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0 or va >= self.fde_ends[self.starts[index]]:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return self.starts[index], self.fde_ends[self.starts[index]]

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        self.offset(start, end - start, executable=True)
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

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map


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
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at", "data")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None, rip_at=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)
        self.rip_at = rip_at


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
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
    if byte == 0xCC:
        return finish("int3")
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
            return finish("pushm", rm, w=8)
        raise EvidenceError("unsupported group 5 opcode at %#x" % va)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
        if two == 0x13 and not opsize:
            reg, rm = modrm(True)
            return finish("movlps", rm, ("x", reg), 8)
        if 0xC8 <= two <= 0xCF:
            return finish("bswap", ("r", (two & 7) | ((rex & 1) << 3)), w=width)
        if two == 0xC6 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("shufpd", ("x", reg), rm, 16, target=value)
        if two == 0xC2 and opsize:
            reg, rm = modrm(True)
            value = immediate(1) & 0xFF
            return finish("cmppd", ("x", reg), rm, 16, target=value)
        if two == 0x50 and opsize:
            reg, rm = modrm(True)
            return finish("movmskpd", ("r", reg), rm, 4)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x14, True): "punpcklqdq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0x51 and repne:
            reg, rm = modrm(True)
            return finish("sqrtsd", ("x", reg), rm, 8)
        if two == 0xD4 and opsize:
            reg, rm = modrm(True)
            return finish("paddq", ("x", reg), rm, 16)
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0xB0, 0xB1, 0xC0, 0xC1):
            reg, rm = modrm()
            return finish("cold", rm, ("r", reg), 1 if two in (0xB0, 0xC0) else width)
        if two == 0x2C and repne:
            reg, rm = modrm(True)
            return finish("cvttsd2si", ("r", reg), rm, 8)
        if two == 0x2A and repne:
            reg, rm = modrm()
            return finish("cvtsi2sd", ("x", reg), rm, 8)
        if two == 0x2E and opsize:
            reg, rm = modrm(True)
            return finish("ucomisd", ("x", reg), rm, 8)
        if two == 0x6E and opsize and not wide:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 4)
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
        if two == 0x7E and rep:
            reg, rm = modrm(True)
            return finish("movq", ("x", reg), rm, 8)
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
            return finish("btr", rm, ("r", reg), width)
        if two == 0xBD:
            reg, rm = modrm()
            return finish("bsr", ("r", reg), rm, width)
        if two == 0xA4:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shld", rm, ("r", reg), width, target=value)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrdi", rm, ("r", reg), width, target=value)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
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
        row.data = bytes(read(va, row.size))
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

    def reset(self, used=None):
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
        if not count:
            return b""
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return bytes(buffer[at:at + count])
        if addr in self.statics:
            return (self.statics[addr] & ((1 << 8 * count) - 1)).to_bytes(count, "little")
        try:
            offset = self.image.offset(addr, count)
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
        self.hops = {}
        self.regs = [0] * 16
        self.xmm = [POISON | POISON << 64] * 16
        self.cf = self.zf = self.sf = self.of = self.pf = False
        self.seen = set()
        self.branch_outcomes = {}
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

    def read_code(self, va, count):
        offset = self.image.offset(va, count, executable=True)
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
        self.keep_rdx = False
        hook(self)
        for reg in VOLATILE:
            self.regs[reg] = POISON
        if not self.keep_rdx:
            self.regs[RDX] = POISON
        self.xmm = [POISON | POISON << 64] * 16

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
            hop = self.hops.get(pc)
            if hop:
                pc = hop(self)
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
            taken = self.condition(row.cc)
            self.branch_outcomes.setdefault(row.va, set()).add(taken)
            return row.target if taken else row.next
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
        elif op == "jmp":
            hook = self.calls.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "bt":
            self.cf = bool(self.get(row.a, width) >> (row.b[1] & (8 * width - 1)) & 1)
        elif op == "calli":
            target = self.get(row.a, 8)
            if target in self.real:
                self.push(row.next)
                return target
            hook = self.slots.get(target)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.xmm_result = None
            self.stub(hook)
            if self.xmm_result is not None:
                self.xmm[0] = self.xmm_result
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
        elif op == "imul1":
            left = self.regs[RAX] - (1 << 64) if self.regs[RAX] & SIGN[8] else self.regs[RAX]
            value = self.get(row.a, 8)
            product = left * (value - (1 << 64) if value & SIGN[8] else value)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "imul3":
            self.put(row.a, width, self.get(row.b, width) * row.target)
        elif op in ("shl", "shr", "sar"):
            count = (self.regs[RCX] if row.b[0] == "r" else row.b[1]) & (63 if width == 8 else 31)
            value = self.get(row.a, width)
            if op == "shl":
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
        elif op == "movlps":
            self.memory.write(self.address(row.a), 8, self.xmm[row.b[1]] & MASK[8])
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            self.put(row.a, width, self.get(row.a, width) * self.get(row.b, width))
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd", "shrdi"):
            bits = 8 * width
            count = (self.regs[RCX] if op == "shrd" else row.target) & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            if op == "shld":
                value = (high << count | low >> (bits - count)) if count else high
            else:
                value = (high >> count | low << (bits - count)) if count else high
            self.put(row.a, width, value)
        elif op == "ror":
            bits = 8 * width
            count = self.get(row.b, 1) & (bits - 1)
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) if count else value)
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
                self.xmm[row.a[1]] = self.get(row.b, 8)
            else:
                self.put(row.a, 8, self.xmm[row.b[1]] & MASK[8])
        elif op in ("addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            if op == "addsd":
                result = left + right
            elif op == "divsd":
                result = left / right
            elif op == "subsd":
                result = left - right
            elif op == "mulsd":
                result = left * right
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
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "unpckhpd":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 | (self.vector(row.b) >> 64) << 64
        elif op == "punpckldq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left & MASK[4]) | (right & MASK[4]) << 32 | ((left >> 32) & MASK[4]) << 64 | ((right >> 32) & MASK[4]) << 96
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, 4)
        elif op == "punpcklbw":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(byte for pair in zip(left[:8], right[:8]) for byte in pair), "little")
        elif op == "pshuflw":
            source = self.vector(row.b)
            words = [(source >> (16 * index)) & 0xFFFF for index in range(4)]
            low = sum(words[(row.target >> (2 * index)) & 3] << (16 * index) for index in range(4))
            self.xmm[row.a[1]] = source >> 64 << 64 | low
        elif op == "pshufd":
            source = self.vector(row.b)
            words = [(source >> (32 * index)) & MASK[4] for index in range(4)]
            self.xmm[row.a[1]] = sum(words[(row.target >> (2 * index)) & 3] << (32 * index) for index in range(4))
        elif op in ("pcmpeqb", "pcmpeqd"):
            size = 1 if op == "pcmpeqb" else 4
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            lanes = (b"\xff" * size if left[at:at + size] == right[at:at + size] else bytes(size) for at in range(0, 16, size))
            self.xmm[row.a[1]] = int.from_bytes(b"".join(lanes), "little")
        elif op == "pmovmskb":
            data = self.xmm[row.b[1]].to_bytes(16, "little")
            self.put(row.a, 4, sum((byte >> 7) << index for index, byte in enumerate(data)))
        elif op == "tzcnt":
            source = self.get(row.b, row.width)
            count = (source & -source).bit_length() - 1 if source else row.width * 8
            self.cf = source == 0
            self.zf = count == 0
            self.put(row.a, row.width, count)
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op == "shufpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            first = (left >> (64 * (row.target & 1))) & MASK[8]
            second = (right >> (64 * ((row.target >> 1) & 1))) & MASK[8]
            self.xmm[row.a[1]] = first | second << 64
        elif op == "cmppd":
            if row.target != 5:
                raise Halt("unmodelled compare predicate at %#x" % row.va)
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            value = 0
            for shift in (0, 64):
                if not to_float((left >> shift) & MASK[8]) < to_float((right >> shift) & MASK[8]):
                    value |= MASK[8] << shift
            self.xmm[row.a[1]] = value
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "divpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = to_bits(to_float(left & MASK[8]) / to_float(right & MASK[8])) | to_bits(to_float(left >> 64) / to_float(right >> 64)) << 64
        elif op == "sqrtsd":
            self.set_low(row.a[1], to_bits(math.sqrt(to_float(self.low(row.b)))))
        elif op == "paddq":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = ((left & MASK[8]) + (right & MASK[8])) & MASK[8] | (((left >> 64) + (right >> 64)) & MASK[8]) << 64
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


# These routines are in the reward-stage output path, after reward calculation.
FUNCTIONS = {
    0x33879D0: "short_sort",
    0x3BC1610: "long_sort_entry",
    0x3865C20: "sort_driver",
    0x38879E0: "sort_partition",
    0x33903C0: "sort_small_partition",
    0x3862E60: "sort_pivot",
    0x2FBE050: "bulk_tree",
}
INDIRECT_SORT = 0x5775F18
INDIRECT_SORT_TARGET = 0x38879E0
SLOTS = {
    0x576DFB8: "capacity_failure", 0x576DFD8: "allocate", 0x576DFE0: "copy",
    0x576E010: "free", 0x576E020: "allocation_failure", 0x576E0E0: "move",
    0x576E108: "assertion", 0x576E470: "other_failure", 0x576E488: "compare",
    0x5775CB0: "long_sort", 0x5775F18: "partition",
}
# Pins bind the selector in the previously studied stage host to this path.
PINS = {
    0x337372D: ("empty_test", "4d85e40f84bc000000"),
    0x337373E: ("one_test", "4983fc010f8527050000"),
    0x3373C6F: ("small_threshold", "4983fc15733e"),
    0x3373C7B: ("short_sort_call", "e8503d0100"),
    0x3373CC1: ("long_sort_slot_call", "ff15e91f4002"),
    0x33737D6: ("bulk_call", "e875a8c4ff"),
    0x3387A4C: ("key_width", "ba14000000"),
    0x3387A56: ("short_order", "85c079db"),
    0x2FBE286: ("same_key", "81f9ffff00007522"),
    0x2FBE2DF: ("node_capacity", "4883f80b"),
    0x3BC1639: ("long_buffer_cap", "4881fe400d0300"),
    0x3BC165E: ("stack_buffer_limit", "4983fd67"),
    0x3BE56F6: ("producer_stride", "4b8d14bf"),
    0x3BE5707: ("producer_key_tail", "498974d010"),
    0x3BE5712: ("producer_key_head", "66410f1104d0"),
    0x3BE5718: ("producer_tag", "49894cd018"),
    0x3BE571D: ("producer_value", "498944d020"),
}
ARRAY = HEAP_BASE + 0x1000
ITER = HEAP_BASE + 0x40000
ROOT_NODE = HEAP_BASE + 0x40100
ROOT_CELL = HEAP_BASE + 0x40400
COUNT = HEAP_BASE + 0x40420
ARENA = HEAP_BASE + 0x50000
MARKER = 0x7700000000



def selected_relocations(image):
    grouped = {slot: [] for slot in SLOTS}
    for slot, kind, addend, symbol in image.relocations():
        if slot in grouped:
            grouped[slot].append((kind, addend, symbol))
    symbols = image.named[".dynsym"]
    strings = image.named[".dynstr"]
    result = []
    for slot in sorted(SLOTS):
        if len(grouped[slot]) != 1:
            raise EvidenceError("ambiguous relocation")
        kind, addend, symbol = grouped[slot][0]
        name = ""
        if symbol:
            if symbol * 24 + 24 > symbols["size"]:
                raise EvidenceError("dynamic symbol outside section")
            pos = struct.unpack_from("<I", image.blob, symbols["offset"] + symbol * 24)[0]
            if pos >= strings["size"]:
                raise EvidenceError("dynamic name outside string table")
            begin = strings["offset"] + pos
            end = image.blob.find(b"\0", begin, strings["offset"] + strings["size"])
            if end < 0:
                raise EvidenceError("unterminated dynamic name")
            name = bytes(image.blob[begin:end]).decode("ascii")
        result.append((SLOTS[slot], hex(slot), kind, symbol, hex(addend), name))
    return result

def checked_pins(image):
    rows = []
    for va, (name, expected) in sorted(PINS.items()):
        offset = image.offset(va)
        raw = bytes(image.blob[offset:offset + len(bytes.fromhex(expected))])
        if raw.hex() != expected:
            raise EvidenceError("instruction pin mismatch at %#x" % va)
        rows.append((name, va, offset, raw.hex()))
    rels = {int(r[1], 16): r for r in selected_relocations(image)}
    for slot, target in ((INDIRECT_SORT, INDIRECT_SORT_TARGET), (0x5775CB0, 0x3BC1610)):
        if rels[slot][2:5] != (8, 0, hex(target)):
            raise EvidenceError("sort relocation mismatch")
    for slot, name in ((0x576DFE0, "memcpy"), (0x576E0E0, "memmove"), (0x576E488, "memcmp")):
        if rels[slot][2] != 6 or rels[slot][5] != name:
            raise EvidenceError("memory import relocation mismatch")
    return rows


def row(key, tag, value, serial=0):
    if not 0 <= key < 1 << 160 or tag not in (0, 1) or not 0 <= value <= MASK[8]:
        raise ValueError("invalid input row")
    return key.to_bytes(20, "big") + struct.pack("<IQQ", serial, tag, value)


def unpack_row(data):
    return (data[:20], *struct.unpack_from("<QQ", data, 24))


def model(rows):
    # Stable sort followed by last-value-wins for adjacent equal 20-byte keys.
    ordered = sorted(rows, key=lambda x: x[:20])
    output = []
    for item in ordered:
        triple = unpack_row(item)
        if output and output[-1][0] == triple[0]:
            output[-1] = triple
        else:
            output.append(triple)
    return ordered, output


class Runner:
    def __init__(self, image, patches=None, fail_at=None, fresh_byte=0xA5, compare_magnitude=1, sort_context=ITER):
        if not 0 <= fresh_byte <= 255 or not 1 <= compare_magnitude <= 0x7FFFFFFF:
            raise ValueError("invalid fixture control")
        self.fresh_byte = fresh_byte
        self.compare_magnitude = compare_magnitude
        self.sort_context = sort_context
        self.topology = []
        self.image = image
        self.m = Machine(image, patches)
        self.mem = self.m.memory
        self.m.real = frozenset(FUNCTIONS)
        self.next = ARENA
        self.allocations = []
        self.sort_allocations = []
        self.frees = []
        self.fail_at = fail_at
        self.m.memory.statics[INDIRECT_SORT] = INDIRECT_SORT_TARGET
        hooks = {
            0x576E488: self.compare,
            0x576DFD8: self.alloc,
            0x576DFB8: self.fail,
            0x576E020: self.fail,
            0x576E108: self.fail,
            0x576E470: self.fail,
            0x576E010: self.free,
            0x576DFE0: self.copy,
            0x576E0E0: self.copy,
        }
        for slot, hook in hooks.items():
            marker = MARKER + slot
            self.mem.statics[slot] = marker
            self.m.slots[marker] = hook

    def allocate(self, size):
        if size > HEAP_BASE + HEAP_SIZE - self.next:
            raise Halt("fixture arena exhausted")
        addr = self.next
        self.next += (size + 15) & ~15
        self.mem.put_bytes(addr, bytes([self.fresh_byte]) * size)
        return addr

    def alloc(self, m):
        size = m.regs[RDI]
        self.allocations.append(size)
        if self.fail_at == len(self.allocations):
            m.regs[RAX] = 0
        else:
            m.regs[RAX] = self.allocate(size)

    def compare(self, m):
        left, right, count = (m.regs[r] for r in (RDI, RSI, RDX))
        if count != 20:
            raise Halt("unexpected comparison width")
        a, b = self.mem.bytes_at(left, count), self.mem.bytes_at(right, count)
        m.regs[RAX] = (((a > b) - (a < b)) * self.compare_magnitude) & MASK[4]

    def copy(self, m):
        dst, src, count = (m.regs[r] for r in (RDI, RSI, RDX))
        if count > HEAP_SIZE:
            raise Halt("copy exceeds arena")
        self.mem.copy(dst, src, count)
        m.regs[RAX] = dst

    def free(self, m):
        addr, size = m.regs[RDI], m.regs[RSI]
        if size and not (addr == ARRAY or ARENA <= addr < self.next):
            raise Halt("unexpected free")
        self.frees.append(size)

    def fail(self, m):
        raise Panicked("target failure sink")

    def tree(self, root, height, count):
        seen = set()
        def visit(node, depth, parent, index, path):
            if node in seen or not HEAP_BASE <= node < HEAP_BASE + HEAP_SIZE:
                raise Halt("invalid or repeated node")
            seen.add(node)
            n = self.mem.read(node + 0x196, 2)
            if n > 11 or (parent is not None and n < 5):
                raise Halt("invalid node occupancy")
            if parent is not None and (self.mem.read(node + 0xB0, 8) != parent or
                                       self.mem.read(node + 0x194, 2) != index):
                raise Halt("broken parent link")
            first = self.mem.bytes_at(node + 0xB8, 20).hex() if n else ""
            last = self.mem.bytes_at(node + 0xB8 + 20 * (n - 1), 20).hex() if n else ""
            self.topology.append((path, depth, n, first, last))
            result = []
            for i in range(n):
                if depth:
                    result.extend(visit(self.mem.read(node + 0x198 + 8 * i, 8), depth - 1, node, i, path + "." + str(i)))
                key = self.mem.bytes_at(node + 0xB8 + 20 * i, 20)
                tag = self.mem.read(node + 16 * i, 8)
                value = self.mem.read(node + 16 * i + 8, 8)
                result.append((key, tag, value))
            if depth:
                result.extend(visit(self.mem.read(node + 0x198 + 8 * n, 8), depth - 1, node, n, path + "." + str(n)))
            return result
        found = visit(root, height, None, 0, "root")
        if len(found) != count or any(a[0] >= b[0] for a, b in zip(found, found[1:])):
            raise Halt("tree count or ordering mismatch")
        return found, len(seen)

    def run(self, rows, presorted=False):
        if any(len(x) != 40 for x in rows) or len(rows) > 4096:
            raise ValueError("invalid fixture size")
        count = len(rows)
        self.mem.put_bytes(ARRAY, b"".join(rows))
        # The host supplies a pointer to a closure context; keep it file-independent.
        self.mem.write(ITER, 8, ROOT_CELL)
        self.mem.write(ROOT_CELL, 8, ARRAY)
        if not presorted and count > 1:
            entry = 0x33879D0 if count < 21 else 0x3BC1610
            self.m.run(entry, {RDI: ARRAY, RSI: count, RDX: self.sort_context})
        self.sort_allocations = list(self.allocations)
        ordered = [self.mem.bytes_at(ARRAY + 40 * i, 40) for i in range(count)]
        if not count:
            return ordered, [], 0, 0
        self.mem.put_bytes(ROOT_NODE, bytes([self.fresh_byte]) * 0x198)
        self.mem.write(ROOT_NODE + 0xB0, 8, 0)
        self.mem.write(ROOT_NODE + 0x196, 2, 0)
        self.mem.write(ROOT_CELL, 8, ROOT_NODE)
        self.mem.write(ROOT_CELL + 8, 8, 0)
        self.mem.write(COUNT, 8, 0)
        self.mem.put_bytes(ITER, bytes(0x48))
        self.mem.write(ITER, 8, ARRAY)
        self.mem.write(ITER + 8, 8, ARRAY)
        self.mem.write(ITER + 0x10, 8, count)
        self.mem.write(ITER + 0x18, 8, ARRAY + count * 40)
        self.mem.write(ITER + 0x38, 8, 3)
        self.m.run(0x2FBE050, {RDI: ROOT_CELL, RSI: ITER, RDX: COUNT})
        root, height = self.mem.read(ROOT_CELL, 8), self.mem.read(ROOT_CELL + 8, 8)
        result, nodes = self.tree(root, height, self.mem.read(COUNT, 8))
        return ordered, result, height, nodes


def fixtures():
    cases = [("empty", []), ("one_none", [row(9, 0, 123, 7)]),
             ("one_some", [row(9, 1, 123, 7)]),
             ("duplicate_last_none", [row(4, 1, 80, 0), row(4, 0, 93, 1)]),
             ("duplicate_last_some", [row(4, 0, 80, 0), row(4, 1, 93, 1)]),
             ("byte_order", [row(1 << 152, 1, 4), row(255, 1, 5), row(1 << 64, 0, 6)])]
    lengths = (2, 3, 5, 10, 11, 12, 13, 19, 20, 21, 22, 31, 32, 33,
               63, 64, 65, 101, 102, 103, 104, 203, 204, 205, 206,
               255, 256, 257, 499, 500, 999, 1000, 1727, 1728, 2048, 4096)
    for n in lengths:
        for mode in ("reverse", "duplicates"):
            rows = []
            for i in range(n):
                key = n - i if mode == "reverse" else (i * 37 + 11) % max(1, n // 3)
                # The payload is unique even when keys and tags match.
                rows.append(row(key, (i + n) & 1, ((n << 32) | i), i))
            cases.append(("%s_%04d" % (mode, n), rows))
    # Separate controls distinguish stability across distant equal keys.
    for n in (102, 103, 205):
        cases.append(("all_equal_%03d" % n, [row(17, i & 1, i, i) for i in range(n)]))
    cases.append(("already_sorted_206", [row(i, i & 1, i, i) for i in range(206)]))
    for n in (21, 32, 33, 64, 65, 102, 103, 127, 128, 129, 255, 256, 257, 512, 1024):
        for pattern in ("alternating", "organ_pipe"):
            values = []
            for i in range(n):
                key = (i // 2 if i & 1 else n - i // 2) if pattern == "alternating" else min(i, n - 1 - i)
                values.append(row(key, i & 1, (n << 32) | i, i))
            cases.append(("%s_%04d" % (pattern, n), values))
    for n in range(2, 6):
        for index, keys in enumerate(itertools.permutations(range(n))):
            cases.append(("permutation_%d_%03d" % (n, index),
                          [row(key, i & 1, i, i) for i, key in enumerate(keys)]))
    for index, keys in enumerate(sorted(set(itertools.permutations((0, 0, 1, 1, 2))))):
        cases.append(("multiset_%02d" % index, [row(key, i & 1, i, i) for i, key in enumerate(keys)]))
    for seed in range(32):
        n = 17 + (seed * 29) % 170
        vals = []
        for i in range(n):
            h = hashlib.sha256(struct.pack("<II", seed, i % (1 + n // 3))).digest()
            vals.append(h[:20] + struct.pack("<IQQ", i, (i + seed) & 1, (seed << 32) | i))
        cases.append(("mixed_%02d" % seed, vals))
    return cases


def rows_digest(rows):
    return hashlib.sha256(b"".join(rows)).hexdigest()


def result_digest(rows):
    return hashlib.sha256(b"".join(k + struct.pack("<QQ", tag, value) for k, tag, value in rows)).hexdigest()


def evaluate(image, name, rows):
    expected_sort, expected_tree = model(rows)
    run = Runner(image)
    actual_sort, actual_tree, height, nodes = run.run(rows)
    if actual_sort != expected_sort or actual_tree != expected_tree:
        raise EvidenceError("model mismatch in " + name)
    return (name, len(rows), len(actual_tree), height, nodes, len(run.allocations),
            len(run.frees), run.m.steps, len(run.m.seen), rows_digest(rows),
            rows_digest(actual_sort), result_digest(actual_tree), len(run.sort_allocations),
            sum(run.sort_allocations)), run.m.seen, run.m.branch_outcomes, (actual_sort, actual_tree, height, nodes, run.allocations, run.frees, run.topology)



def damaged_copy(image, va):
    blob = bytearray(image.blob)
    blob[image.offset(va)] ^= 1
    return Image(blob)


def damaged_relocation(image, slot):
    rela = image.named[".rela.dyn"]
    offsets = [pos for pos in range(rela["offset"], rela["offset"] + rela["size"], 24)
               if struct.unpack_from("<Q", image.blob, pos)[0] == slot]
    if len(offsets) != 1:
        raise EvidenceError("ambiguous relocation to corrupt")
    blob = bytearray(image.blob)
    blob[offsets[0] + 16] ^= 1
    return Image(blob)

def controls(image):
    outcomes = []
    def rejected(name, fn, errors):
        try:
            fn()
        except errors:
            outcomes.append((name, "rejected"))
            return
        raise EvidenceError("control accepted: " + name)
    rejected("wrong_sha256", lambda: load_image(BINARY, "0" * 64), (EvidenceError,))
    rejected("outside_file_backed_sections", lambda: image.offset(1 << 63), (EvidenceError,))
    rejected("outside_function", lambda: image.exact_fde(1 << 63), (EvidenceError,))
    rejected("corrupt_selector_pin", lambda: checked_pins(damaged_copy(image, 0x3373C72)), (EvidenceError,))
    rejected("corrupt_sort_relocation", lambda: checked_pins(damaged_relocation(image, INDIRECT_SORT)), (EvidenceError,))
    rejected("bad_row_tag", lambda: row(0, 2, 1), (ValueError,))
    rejected("out_of_order_tree", lambda: Runner(image).run([row(2, 1, 1), row(1, 1, 2)], presorted=True), (Halt,))
    rejected("allocation_failure_long_sort", lambda: Runner(image, fail_at=1).run([row(i, 1, i) for i in range(205, 0, -1)]), (Panicked,))
    rejected("allocation_failure_tree", lambda: Runner(image, fail_at=1).run([row(i, 1, i) for i in range(12)]), (Panicked,))
    def sort_mutation():
        original = [row(3, 1, 1), row(2, 1, 2), row(1, 1, 3)]
        actual, result, _, _ = Runner(image, patches={0x3387A58: 0x78}).run(original)
        if (actual, result) != model(original):
            raise EvidenceError("mutant distinguished")
    rejected("flip_short_sort_comparison", sort_mutation, (EvidenceError, Halt))
    def duplicate_mutation():
        original = [row(1, 1, 5), row(1, 0, 9)]
        actual, result, _, _ = Runner(image, patches={0x2FBE28C: 0x74}).run(original)
        if (actual, result) != model(original):
            raise EvidenceError("mutant distinguished")
    rejected("flip_duplicate_branch", duplicate_mutation, (EvidenceError, Halt))
    def capacity_mutation():
        rows = [row(i, 1, i) for i in range(11)]
        sorted_rows, tree_rows, height, nodes = Runner(image, patches={0x2FBE2E2: 10}).run(rows)
        if (height, nodes) != (0, 1):
            raise EvidenceError("tree shape distinguished")
    rejected("change_leaf_capacity", capacity_mutation, (EvidenceError, Halt))
    def inner_sort_mutation():
        rows = [row(i, 1, i) for i in (3, 2, 1)]
        actual = Runner(image, patches={0x3387ABC: 0x79}).run(rows)
        if actual[:2] != model(rows):
            raise EvidenceError("mutant distinguished")
    rejected("flip_inner_sort_branch", inner_sort_mutation, (EvidenceError, Halt))
    rows = [row((i * 17) % 29, i & 1, i, i) for i in range(103)]
    filled = []
    for byte in (0, 0xA5, 0xFF):
        run = Runner(image, fresh_byte=byte)
        filled.append((run.run(rows), run.topology))
    if filled[0] != filled[1] or filled[1] != filled[2]:
        raise EvidenceError("allocator fill changed observed tree")
    outcomes.append(("allocator_fill_invariance", "passed"))
    compared = []
    for magnitude in (1, 255, 0x7FFFFFFF):
        run = Runner(image, compare_magnitude=magnitude)
        compared.append((run.run(rows), run.topology))
    if compared[0] != compared[1] or compared[1] != compared[2]:
        raise EvidenceError("comparison magnitude changed observed tree")
    outcomes.append(("compare_magnitude_invariance", "passed"))
    context_outcomes = []
    for pointer in (0, ITER):
        run = Runner(image, sort_context=pointer)
        context_outcomes.append((run.run(rows), run.topology))
    if context_outcomes[0] != context_outcomes[1]:
        raise EvidenceError("sort context changed observed tree")
    outcomes.append(("sort_context_invariance", "passed"))
    return outcomes



def mutation_campaign(image, decoded, records):
    """Flip each reached conditional; compare bounded cases and retain all outcomes."""
    result = []
    for start, role in sorted(FUNCTIONS.items()):
        for ins in decoded[start]:
            if ins.op != "jcc":
                continue
            candidates = [r for r in records if ins.va in r[2]]
            if not candidates:
                continue
            candidates.sort(key=lambda r: (r[4], r[0]))
            selected = []
            for direction in (None, True, False):
                choice = next((r for r in candidates if r not in selected and
                               (direction is None or direction in r[2][ins.va])), None)
                if choice is not None:
                    selected.append(choice)
            if 0x70 <= ins.data[0] <= 0x7f:
                at = ins.va
            elif ins.data[0] == 0x0f and 0x80 <= ins.data[1] <= 0x8f:
                at = ins.va + 1
            else:
                raise EvidenceError("unsupported conditional encoding")
            byte = image.blob[image.offset(at)]
            state, name, stop_type, tried = "survived", "", "", 0
            for name, values, _, expected, steps in selected:
                tried += 1
                run = Runner(image, patches={at: byte ^ 1})
                run.m.step_limit = max(5000, steps * 2 + 100)
                try:
                    ordered, tree, height, nodes = run.run(values)
                    actual = (ordered, tree, height, nodes, run.allocations, run.frees, run.topology)
                    if actual != expected:
                        state = "different"
                        break
                except (Halt, Panicked, EvidenceError, ValueError, IndexError, OverflowError, struct.error) as exc:
                    state, stop_type = "stopped", type(exc).__name__
                    break
            if state == "survived":
                stress = [r for r in candidates if r not in selected and r[4] <= 150000]
                if stress:
                    name, values, _, expected, steps = max(stress, key=lambda r: (r[4], r[0]))
                    tried += 1
                    run = Runner(image, patches={at: byte ^ 1})
                    run.m.step_limit = max(5000, steps * 2 + 100)
                    try:
                        ordered, tree, height, nodes = run.run(values)
                        actual = (ordered, tree, height, nodes, run.allocations, run.frees, run.topology)
                        if actual != expected:
                            state = "different"
                    except (Halt, Panicked, EvidenceError, ValueError, IndexError, OverflowError, struct.error) as exc:
                        state, stop_type = "stopped", type(exc).__name__
            result.append((role, hex(ins.va), hex(at), "%02x" % byte, "%02x" % (byte ^ 1), tried, state, name, stop_type))
    return result

def write_tsv(path, headings, rows):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(headings)
        w.writerows(rows)


def generate(out):
    image = load_image()
    pins = checked_pins(image)
    function_rows, instruction_rows, branches = [], [], []
    decoded = {}
    for start, name in sorted(FUNCTIONS.items()):
        _, end = image.exact_fde(start)
        fde = image.fdes[start]
        off = image.offset(start)
        body = bytes(image.blob[off:off + end - start])
        decoded[start] = decode_range(image, start, end)
        function_rows.append((name, hex(start), hex(end), hex(off), hex(fde["fde"]),
                              hashlib.sha256(body).hexdigest(), len(body), len(decoded[start])))
    cases, reached, outcomes, records = [], set(), {}, []
    for name, values in fixtures():
        result, seen, directions, signature = evaluate(image, name, values)
        cases.append(result)
        records.append((name, values, directions, signature, result[7]))
        reached.update(seen)
        for va, values_seen in directions.items():
            outcomes.setdefault(va, set()).update(values_seen)
    negative = controls(image)
    for start, name in sorted(FUNCTIONS.items()):
        for ins in decoded[start]:
            target = "" if ins.target is None or ins.op not in ("jcc", "jmp", "call") else hex(ins.target)
            instruction_rows.append((name, hex(ins.va), ins.data.hex(), ins.op, target, int(ins.va in reached)))
            if ins.op == "jcc":
                branches.append((name, hex(ins.va), ins.data.hex(), ins.cc, hex(ins.target), hex(ins.next), int(True in outcomes.get(ins.va, set())), int(False in outcomes.get(ins.va, set()))))
    mutations = mutation_campaign(image, decoded, records)
    witness, topology = [], []
    witness_names = {"one_none", "duplicate_last_none", "duplicate_last_some", "byte_order", "reverse_0020", "reverse_0021", "duplicates_0021"}
    topology_names = {"reverse_0011", "reverse_0012", "reverse_0021", "reverse_1728"}
    for name, values, _, signature, _ in records:
        ordered, tree, _, _, _, _, nodes = signature
        if name in witness_names:
            for phase, items in (("input", values), ("sorted", ordered)):
                for index, item in enumerate(items):
                    key, tag, value = unpack_row(item)
                    witness.append((name, phase, index, key.hex(), tag, value, struct.unpack_from("<I", item, 20)[0]))
            for index, (key, tag, value) in enumerate(tree):
                witness.append((name, "tree", index, key.hex(), tag, value, ""))
        if name in topology_names:
            topology.extend((name, *node) for node in nodes)
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / "functions.tsv", ("role", "start_va", "end_va", "file_offset", "fde_va", "body_sha256", "bytes", "instructions"), function_rows)
    write_tsv(out / "anchors.tsv", ("name", "va", "file_offset", "bytes"), [(n, hex(a), hex(o), b) for n, a, o, b in pins])
    write_tsv(out / "relocations.tsv", ("role", "slot_va", "type", "symbol_index", "addend", "dynamic_symbol"), selected_relocations(image))
    write_tsv(out / "instructions.tsv", ("role", "va", "bytes", "operation", "target_va", "reached"), instruction_rows)
    write_tsv(out / "branches.tsv", ("role", "va", "bytes", "condition_code", "taken_va", "fallthrough_va", "taken_seen", "fallthrough_seen"), branches)
    write_tsv(out / "scenarios.tsv", ("case", "input_rows", "tree_rows", "tree_height", "tree_nodes", "allocations", "frees", "steps", "reached_instructions", "input_sha256", "sorted_sha256", "tree_sha256", "sort_allocations", "sort_allocated_bytes"), cases)
    write_tsv(out / "negative-controls.tsv", ("control", "result"), negative)
    write_tsv(out / "mutations.tsv", ("role", "branch_va", "byte_va", "original", "replacement", "cases_tried", "result", "case", "stop_type"), mutations)
    write_tsv(out / "witnesses.tsv", ("case", "phase", "index", "key_hex", "tag", "payload", "input_serial"), witness)
    write_tsv(out / "topology.tsv", ("case", "node_path", "depth", "keys", "first_key_hex", "last_key_hex"), topology)
    summary = {"target_sha256": SHA256, "function_count": len(function_rows),
               "function_bytes": sum(r[6] for r in function_rows),
               "instructions": len(instruction_rows), "conditional_branches": len(branches),
               "reached_instructions": sum(r[-1] for r in instruction_rows),
               "reached_branch_sites": sum(bool(r[-1] or r[-2]) for r in branches),
               "both_branch_directions": sum(bool(r[-1] and r[-2]) for r in branches),
               "scenarios": len(cases), "negative_controls": len(negative),
               "branch_mutants": len(mutations),
               "mutants_different": sum(r[6] == "different" for r in mutations),
               "mutants_stopped": sum(r[6] == "stopped" for r in mutations),
               "mutants_survived": sum(r[6] == "survived" for r in mutations),
               "witness_rows": len(witness), "topology_nodes": len(topology),
               "model_mismatches": 0,
               "scope": "Selected sort and bulk-build bodies, not the complete staking tick or allocator."}
    (out / "summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    generate(args.out)


if __name__ == "__main__":
    main()
