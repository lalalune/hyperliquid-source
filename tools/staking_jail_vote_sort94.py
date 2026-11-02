#!/usr/bin/env python3
"""Static evaluation of node 94 jail-vote sorting and NoVoter cloning.

The decoder and interpreter derive from MIT-licensed staking_stake_accounting.py."""
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


class Trap(Halt):
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
        self.named = {}
        for section in self.sections:
            if section['name'] in self.named:
                raise EvidenceError('duplicate section name')
            self.named[section['name']] = section
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
            if not any(start <= pc < start + size for start, size in SIZES.items()):
                raise Halt("control left selected FDE windows")
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
            self.current_pc = pc
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
        elif op == "ud2":
            raise Trap("UD2 trap at %#x" % row.va)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


FUNCTIONS = {
    0x3bc24a0:'sort_entry', 0x38711a0:'sort_driver', 0x3885de0:'partition',
    0x3384130:'sort_helper', 0x338a9d0:'small_partition', 0x3860f60:'pivot', 0x33e7840:'no_voter_clone',
    0x2f0a230:'no_voter_failure',
}
SIZES = {0x3384130:585, 0x3bc24a0:329, 0x38711a0:2164, 0x3885de0:1863, 0x338a9d0:1502,
         0x3860f60:376, 0x33e7840:424, 0x2f0a230:19}
ARRAY = HEAP_BASE+0x1000
CONTEXT = HEAP_BASE+0x80000
ARENA = HEAP_BASE+0x100000
MARKER = 0x7700000000


def make_row(date, seconds, fraction, weight, serial):
    if not -(1<<31) <= date < (1<<31) or not 0<=seconds<1<<32 or not 0<=fraction<1<<32 or not 0<=weight<1<<64 or not 0<=serial<1<<32:
        raise ValueError('invalid row field')
    return struct.pack('<iIIIQ',date,seconds,fraction,serial,weight)


def order(row):
    return struct.unpack_from('<iII',row)+(struct.unpack_from('<Q',row,16)[0],)


class Runner:
    def __init__(self,image,patches=None,fail_at=None):
        self.image=image
        self.machine=Machine(image,patches)
        self.mem=self.machine.memory
        self.machine.real=frozenset(FUNCTIONS)
        self.mem.statics[0x5775fd0]=0x3885de0
        self.next=ARENA
        self.allocations=[]
        self.frees=[]
        self.fail_at=fail_at
        self.failure=None
        for slot,hook in {0x576dfd8:self.alloc,0x576dfb8:self.fail,
                          0x576e010:self.free,0x576dfe0:self.copy,
                          0x576e098:self.fail,0x576e2e0:self.fail,
                          0x576e020:self.fail,0x576e470:self.fail,
                          0x57706c8:self.no_voter}.items():
            self.mem.statics[slot]=MARKER+slot
            self.machine.slots[MARKER+slot]=hook

    def alloc(self,m):
        size=m.regs[RDI]
        self.allocations.append(size)
        if self.fail_at==len(self.allocations):
            m.regs[RAX]=0
            return
        if self.next+size>HEAP_BASE+HEAP_SIZE: raise Halt('fixture arena exhausted')
        p=self.next;self.next+=(size+15)&~15
        self.mem.put_bytes(p,b'\xa5'*size)
        m.regs[RAX]=p

    def copy(self,m):
        dst,src,n=(m.regs[r] for r in (RDI,RSI,RDX))
        if n>HEAP_SIZE or (n and dst<src+n and src<dst+n): raise Halt('invalid memcpy')
        self.mem.copy(dst,src,n);m.regs[RAX]=dst

    def free(self,m):
        p,n=m.regs[RDI],m.regs[RSI]
        if not ARENA<=p<self.next: raise Halt('unexpected free')
        self.frees.append(n)

    def fail(self,m):
        self.failure=(m.current_pc,m.regs[RDI],m.regs[RSI])
        raise Panicked('failure boundary at %#x'%m.current_pc)

    def no_voter(self,m):
        pointer,length=m.regs[RDI],m.regs[RSI]
        raw=self.mem.bytes_at(pointer,length)
        if raw != DIAGNOSTIC: raise Halt('unexpected NoVoter text')
        self.failure=(m.current_pc,raw.decode('ascii'))
        raise Panicked('NoVoter boundary at %#x'%m.current_pc)

    def sort(self,rows):
        if not 21<=len(rows)<=8192 or any(len(x)!=24 for x in rows):
            raise ValueError('expected 21..8192 rows of 24 bytes')
        n=len(rows)
        self.mem.put_bytes(ARRAY-24,b'\x6d'*24)
        self.mem.put_bytes(ARRAY+24*n,b'\x93'*24)
        self.mem.put_bytes(ARRAY,b''.join(rows))
        self.machine.run(0x3bc24a0,{RDI:ARRAY,RSI:n,RDX:CONTEXT})
        if self.mem.bytes_at(ARRAY-24,24)!=b'\x6d'*24 or self.mem.bytes_at(ARRAY+24*n,24)!=b'\x93'*24:
            raise Halt('sort overran array')
        return [self.mem.bytes_at(ARRAY+24*i,24) for i in range(n)]


def evaluate_sort(image,rows,patches=None):
    runner=Runner(image,patches)
    actual=runner.sort(rows)
    expected=sorted(rows,key=order)
    if actual!=expected: raise Halt('sorted result differs from independent rule')
    n=len(rows)
    wanted=max(min(n,333333),n-n//2)
    expected_alloc=[] if wanted<171 else [24*max(wanted,48)]
    if runner.allocations!=expected_alloc or runner.frees!=expected_alloc:
        raise Halt('allocation or free sizes differ')
    return runner,actual


def clone_probe(image,height=0,nonempty_level=None,fail_at=None,patches=None):
    if not 0<=height<=8 or (nonempty_level is not None and not 0<=nonempty_level<=height):
        raise ValueError('invalid clone fixture')
    runner=Runner(image,patches=patches,fail_at=fail_at)
    src=HEAP_BASE+0x20000
    nodes=[src+0x100*i for i in range(height+1)]
    for level,p in enumerate(nodes):
        runner.mem.put_bytes(p,bytes(0xf0 if level else 0x90))
        runner.mem.write(p+0x8e,2,int(level==nonempty_level))
        if level: runner.mem.write(p+0x90,8,nodes[level-1])
    out=HEAP_BASE+0x22000
    runner.mem.put_bytes(out,bytes(24))
    try:
        runner.machine.run(0x33e7840,{RDI:out,RSI:nodes[height],RDX:height})
    except Panicked:
        if nonempty_level is None and fail_at is None: raise
        return runner,'no_voter' if runner.failure and len(runner.failure)==2 else 'failure'
    if nonempty_level is not None or fail_at is not None:
        raise Halt('expected clone boundary not reached')
    root=runner.mem.read(out,8)
    if runner.mem.read(out+8,8)!=height or runner.mem.read(out+16,8)!=0:
        raise Halt('empty clone result metadata mismatch')
    for level in range(height,-1,-1):
        if not ARENA<=root<runner.next or runner.mem.read(root+0x8e,2):
            raise Halt('bad cloned node')
        if level:
            child=runner.mem.read(root+0x90,8)
            if runner.mem.read(child,8)!=root or runner.mem.read(child+0x8c,2)!=0:
                raise Halt('bad cloned backlink')
            root=child
    if runner.allocations != [0x90]+[0xf0]*height:
        raise Halt('clone allocation sequence mismatch')
    return runner,'empty'


HASHES = {
    0x2f0a230:'c433c145c2338a5f8b04194b7e527e55a5e75fe1c6cbc57b453b36dd57caa646',
    0x3384130:'6250fdf65a9496f05726ec10565b92043fb811a95ee5a91360a118e9af90bc19',
    0x338a9d0:'26b1aa56abb136c351fded2abe06c33bdb33b10eaf7418305ad100d94a43f608',
    0x33e7840:'fc7747535c8b275002395b83a9b1bdd55bf4d666c8cb8a7dba6f2b597c8ed73a',
    0x3860f60:'97641c7d0b2f931755d6cbe4733c79f226e04c4b140dcdc6025e50033e2b73f2',
    0x38711a0:'153ec019b6369ffadf8d49d02456166290f75db79a8e6b385ac54702cf4ec65b',
    0x3885de0:'2b7d0a1ea073360c0d1f8470fd6c0a90dda14f80336c23ba19f9fe54c8611e76',
    0x3bc24a0:'dbc464429f43f185db0ca69703f49d8e261fc2cfe20e1dafd294d092424bca27',
}
SLOT_TARGETS = {0x576dfb8:0x1346068,0x576dfd8:0x54c06b0,0x576e010:0x54c8cb0,
                0x576e020:0x1345e2a,0x576e098:0x157b810,0x576e2e0:0x157a6f0,
                0x576e470:0x157a9f0,0x57706c8:0x157b620,0x5775fd0:0x3885de0,
                0x5776250:0x3bc24a0}
DIAGNOSTIC=b'attempted to instantiate uninhabited type `hard_quorum_policy::NoVoter`'


def bytes_at(image,va,size,executable=False):
    off=image.offset(va,size,executable=executable)
    return bytes(image.blob[off:off+size])


def call_target(image,site):
    code=bytes_at(image,site,5,True)
    if code[0]!=0xe8: raise EvidenceError('not a direct call')
    return site+5+struct.unpack_from('<i',code,1)[0]


def relocation_records(image):
    rela=image.named['.rela.dyn']
    if rela['type']!=4 or rela['size']%24: raise EvidenceError('bad relocation section')
    wanted=set(SLOT_TARGETS)|{0x576dfe0}
    records={}
    for slot,kind,addend,index in image.relocations():
        if slot not in wanted: continue
        if slot in records: raise EvidenceError('duplicate relocation')
        records[slot]=(kind,addend,index)
    if set(records)!=wanted: raise EvidenceError('missing relocation')
    for slot,target in SLOT_TARGETS.items():
        if records[slot]!=(8,target,0): raise EvidenceError('unexpected relative relocation')
    kind,addend,index=records[0x576dfe0]
    syms,strings=image.named['.dynsym'],image.named['.dynstr']
    if kind!=6 or not index or syms['type']!=11 or strings['type']!=3 or index*24+24>syms['size']:
        raise EvidenceError('bad memcpy relocation')
    nameoffset=struct.unpack_from('<I',image.blob,syms['offset']+index*24)[0]
    if nameoffset>=strings['size']: raise EvidenceError('bad symbol name')
    pos=strings['offset']+nameoffset
    end=image.blob.find(b'\0',pos,strings['offset']+strings['size'])
    if end<0 or bytes(image.blob[pos:end])!=b'memcpy': raise EvidenceError('unexpected copy import')
    return records


def validate_image(image):
    for start,n in SIZES.items():
        if image.exact_fde(start)!=(start,start+n): raise EvidenceError('unexpected FDE')
        if hashlib.sha256(bytes_at(image,start,n,True)).hexdigest()!=HASHES[start]:
            raise EvidenceError('function body mismatch')
    for site,target in ((0x3993f25,0x33e7840),(0x33e799d,0x2f0a230),
                        (0x33e79b4,0x2f0a230),(0x3bc256b,0x38711a0),
                        (0x3885e19,0x338a9d0),(0x3885eb3,0x3860f60),
                        (0x338aa2a,0x3384130)):
        if call_target(image,site)!=target: raise EvidenceError('unexpected call target')
    if bytes_at(image,0x57ada0,len(DIAGNOSTIC))!=DIAGNOSTIC:
        raise EvidenceError('unexpected NoVoter diagnostic')
    if bytes_at(image,0x3994b6d,2,True)!=b'\xff\x15': raise EvidenceError('missing sort call')
    slot=0x3994b73+struct.unpack('<i',bytes_at(image,0x3994b6f,4,True))[0]
    if slot!=0x5776250: raise EvidenceError('unexpected sort slot')
    relocation_records(image)


def sort_fixtures():
    for n in (21,22,31,32,33,63,64,65,127,128,169,170,171,172,257,512):
        for pattern in ('ascending','descending','ties','mixed'):
            rows=[]
            for i in range(n):
                k=i if pattern=='ascending' else n-i if pattern=='descending' else i%3 if pattern=='ties' else (i*37+11)%max(7,n//2)
                dates=(-2147483648,-1,0,1,2147483647)
                date=dates[k%5] if pattern=='mixed' else k//15
                sec=((k*0x1020304)&0xffffffff) if pattern=='mixed' else k%5
                frac=((k*0x8070605)&0xffffffff) if pattern=='mixed' else k%7
                weight=((k*0x101010101010101)&0xffffffffffffffff) if pattern=='mixed' else k%11
                rows.append(make_row(date,sec,frac,weight,i))
            yield '%s_%d'%(pattern,n),rows
    for mask in range(64):
        rows=[make_row(-1 if mask & (1<<(i%6)) else 1,i%2,i%3,i%4,i) for i in range(33)]
        yield 'mask_%02d'%mask,rows
    for field in range(4):
        for n in (21,65,171):
            rows=[]
            for i in range(n):
                vals=[2,3,4,5]
                vals[field]=(n-i if field else (n-i)-n//2)
                rows.append(make_row(*vals,i))
            yield 'field_%d_%d'%(field,n),rows
    for n in (4096,4097):
        rows=[make_row(i%3,(i*7)%11,(i*5)%13,(i*19)%17,i) for i in range(n)]
        yield 'driver_%d'%n,rows


def capacity_probe(image,count):
    if not 0<=count<1<<64: raise ValueError('count outside u64')
    r=Runner(image,fail_at=1)
    try:
        r.machine.run(0x3bc24a0,{RDI:ARRAY,RSI:count,RDX:CONTEXT})
    except Panicked:
        wanted=max(min(count,333333),count-count//2)
        if wanted<171: raise Halt('count does not reach allocation boundary')
        ceiling=count-count//2
        if ceiling>0x555555555555555:
            if r.allocations or r.failure[0]!=0x3bc2523: raise Halt('wrong size guard')
        else:
            if r.allocations!=[24*max(wanted,48)] or r.failure[0]!=0x3bc25b1:
                raise Halt('wrong allocator failure')
        return r
    raise Halt('allocation failure not reached')


def small_probe(image,count,capacity):
    if not 0<=count<=32 or not 0<=capacity<=64: raise ValueError('invalid small fixture')
    r=Runner(image)
    rows=[make_row((i*7)%5-2,i%3,i%4,i%7,i) for i in range(count)][::-1]
    r.mem.put_bytes(ARRAY,b''.join(rows))
    try:
        r.machine.run(0x338a9d0,{RDI:ARRAY,RSI:count,RDX:HEAP_BASE+0x20000,RCX:capacity,R8:CONTEXT})
    except Trap:
        if count<2 or capacity>=count+16: raise Halt('unexpected small sort trap')
        return r,'trap'
    if count>=2 and capacity<count+16: raise Halt('small capacity guard not reached')
    actual=[r.mem.bytes_at(ARRAY+24*i,24) for i in range(count)]
    if actual!=sorted(rows,key=order): raise Halt('small sort differs from independent rule')
    return r,'sorted'


CONTEXT_PINS=(
    ('prior_host_second_map_length',0x3993f08,5),
    ('prior_host_second_map_root',0x3993f0f,4),
    ('prior_host_second_map_height',0x3993f1c,4),
    ('prior_host_clone_call',0x3993f25,5),
    ('prior_host_sort_threshold',0x3994b0a,6),
    ('prior_host_long_sort_slot',0x3994b6d,6),
    ('clone_inner_nonempty',0x33e78d6,15),
    ('clone_leaf_nonempty',0x33e7921,11),
    ('clone_inner_panic_call',0x33e799d,5),
    ('clone_leaf_panic_call',0x33e79b4,5),
    ('no_voter_text_lea',0x2f0a231,7),
    ('no_voter_text_length',0x2f0a238,5),
    ('no_voter_sink',0x2f0a23d,6),
    ('sort_heap_threshold',0x3bc24ee,9),
    ('sort_driver_call',0x3bc256b,5),
    ('driver_partition_slot',0x38712e1,6),
    ('partition_small_call',0x3885e19,5),
    ('partition_pivot_call',0x3885eb3,5),
    ('small_partition_helper',0x338aa2a,5),
)


def write_tsv(path,header,rows):
    with path.open('w',encoding='utf-8',newline='') as stream:
        writer=csv.writer(stream,delimiter='\t',lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(image,out):
    validate_image(image)
    out.mkdir(parents=True,exist_ok=True)
    functions=[];instructions=[];decoded={}
    for start in sorted(SIZES):
        n=SIZES[start];end=start+n;rows=decode_range(image,start,end);decoded[start]=rows
        functions.append((FUNCTIONS[start],hex(start),hex(end),hex(image.offset(start,n,True)),n,len(rows),HASHES[start]))
        for row in rows:
            instructions.append((FUNCTIONS[start],hex(row.va),row.size,row.data.hex(),row.op,
                                 '' if row.target is None else hex(row.target),'' if row.cc is None else row.cc))
    write_tsv(out/'functions.tsv',('role','start_va','exclusive_end_va','file_offset','bytes','instructions','sha256'),functions)
    write_tsv(out/'instructions.tsv',('role','va','size','bytes','operation','target','condition'),instructions)
    write_tsv(out/'context.tsv',('role','va','bytes'),[(name,hex(va),bytes_at(image,va,n,True).hex()) for name,va,n in CONTEXT_PINS])
    write_tsv(out/'diagnostic.tsv',('va','length','ascii','bytes_hex'),
              [(hex(0x57ada0),len(DIAGNOSTIC),bytes_at(image,0x57ada0,len(DIAGNOSTIC)).decode('ascii'),bytes_at(image,0x57ada0,len(DIAGNOSTIC)).hex())])
    rel=relocation_records(image)
    write_tsv(out/'relocations.tsv',('slot_va','type','addend','symbol_index'),
              [(hex(slot),kind,hex(addend),idx) for slot,(kind,addend,idx) in sorted(rel.items())])
    cases=[];witness=[];seen=set();branches={}
    def collect(machine):
        seen.update(machine.seen)
        for va,taken in machine.branch_outcomes.items(): branches.setdefault(va,set()).update(taken)
    for name,rows in sort_fixtures():
        runner,actual=evaluate_sort(image,rows);collect(runner.machine)
        cases.append((name,len(rows),','.join(map(str,runner.allocations)),runner.machine.steps,
                      len(runner.machine.seen),hashlib.sha256(b''.join(actual)).hexdigest()))
        if name in ('mixed_21','ties_65','mixed_171'):
            for i,(before,after) in enumerate(zip(rows,actual)):
                witness.append((name,i,before.hex(),after.hex()))
    write_tsv(out/'sort-cases.tsv',('case','count','alloc_bytes','steps','reached_instructions','output_sha256'),cases)
    write_tsv(out/'sort-witness.tsv',('case','row','input_hex','output_hex'),witness)
    clone_cases=[]
    for height in range(6):
        r,status=clone_probe(image,height=height);collect(r.machine)
        clone_cases.append((height,'none',status,','.join(map(str,r.allocations)),''))
        for level in range(height+1):
            r,status=clone_probe(image,height=height,nonempty_level=level);collect(r.machine)
            if status!='no_voter' or r.failure != (0x2f0a23d,DIAGNOSTIC.decode('ascii')):
                raise Halt('unexpected NoVoter failure')
            clone_cases.append((height,level,status,','.join(map(str,r.allocations)),hex(r.failure[0])))
    write_tsv(out/'clone-cases.tsv',('height','nonempty_level','outcome','alloc_bytes','failure_va'),clone_cases)
    controls=[]
    for n in (171,333333,666666,666667,(1<<64)-1):
        r=capacity_probe(image,n)
        controls.append(('allocation_failure',n,'',hex(r.failure[0]),','.join(map(str,r.allocations))))
    for n in (0,1,2,5,32):
        for cap in sorted({0,max(0,n+15),n+16}):
            r,status=small_probe(image,n,cap)
            controls.append(('small_capacity',n,cap,status,''))
    for h,fail in ((0,1),(1,1),(1,2),(2,2),(2,3)):
        r,status=clone_probe(image,height=h,fail_at=fail)
        if status!='failure' or r.failure[0] not in (0x33e795e,0x33e797f):
            raise Halt('unexpected clone allocation failure')
        controls.append(('clone_allocation',h,fail,hex(r.failure[0]),','.join(map(str,r.allocations))))
    mut_rows=[make_row((i*7)%19-9,(i*17)%23,(i*13)%11,(i*5)%17,i) for i in range(65)][::-1]
    for name,fn in (
        ('scratch_branch',lambda:evaluate_sort(image,mut_rows,patches={0x3bc24f5:0x72})),
        ('signed_date_compare',lambda:evaluate_sort(image,mut_rows,patches={0x338417e:0x92})),
        ('clone_nonempty_branch',lambda:clone_probe(image,height=0,patches={0x33e792a:0x74})),
    ):
        try: fn()
        except (Halt,Panicked,Trap,EvidenceError,ValueError) as exc:
            controls.append(('mutation',name,'',type(exc).__name__,''))
        else: raise EvidenceError('mutation survived '+name)
    write_tsv(out/'controls.tsv',('kind','input','parameter','outcome','alloc_bytes'),controls)
    branch_rows=[]
    for start in sorted(decoded):
        for row in decoded[start]:
            if row.op=='jcc':
                reached=branches.get(row.va,set())
                branch_rows.append((FUNCTIONS[start],hex(row.va),row.data.hex(),hex(row.target),int(False in reached),int(True in reached)))
    write_tsv(out/'branches.tsv',('role','va','bytes','target','fallthrough_seen','taken_seen'),branch_rows)
    summary={'target_sha256':SHA256,'function_count':len(SIZES),'function_bytes':sum(SIZES.values()),
             'instruction_count':len(instructions),'reached_instruction_count':len(seen),
             'conditional_sites':len(branch_rows),'both_edges_seen':sum(int(r[4] and r[5]) for r in branch_rows),
             'sort_cases':len(cases),'clone_cases':len(clone_cases),'controls':len(controls)}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps(generate(load_image(),args.out),sort_keys=True))


if __name__=='__main__':
    try: main()
    except (EvidenceError,Halt,Panicked,OSError,ValueError,struct.error) as error:
        print('staking_jail_vote_sort94: '+str(error),file=sys.stderr)
        sys.exit(1)

# MIT License
# Copyright (c) 2026 Hyperliquid Source contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
