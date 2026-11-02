#!/usr/bin/env python3
"""Trace node 94 delegation-book teardown with a bounded byte interpreter.

The x86 subset decoder and interpreter are adapted from the repository MIT-licensed
tools/staking_stake_accounting.py. ELF and FDE parsing use the shared modules.
No target process or external program is started.
"""
import argparse
import bisect
import collections
import csv
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records, uleb  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
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
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 120000


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
        self.fde_records = {}
        for row in fdes:
            if row["start"] in self.fde_records:
                raise EvidenceError("duplicate FDE start")
            self.fde_records[row["start"]] = row
            ends[row["start"]] = row["end"]
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


def fdiv(left, right):
    return left / right


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
SHIFTS = {0: "rol", 1: "ror", 4: "shl", 5: "shr", 7: "sar"}


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
        elif byte == 0xF0:
            pass
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
            if op != "mov" and any(operand and operand[0] == "r" and 4 <= operand[1] <= 7 for operand in (a, b)):
                raise EvidenceError("high byte register at %#x" % va)
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
    if byte == 0x90:
        return finish("nop")
    if byte == 0x6A:
        value = immediate(1)
        return finish("pushi", ("i", value), w=8)
    if byte == 0x98:
        return finish("cdqe" if wide else "cwde")
    if byte == 0xA9:
        value = immediate(4)
        return finish("test", ("r", RAX), ("i", value), width)
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
    if byte == 0x87:
        reg, rm = modrm()
        return finish("xchg", rm, ("r", reg), width)
    if byte == 0x0F:
        two = window[pos]
        pos += 1
        if two == 0x0B:
            return finish("ud2")
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
        if two == 0x72 and opsize:
            reg, rm = modrm(True)
            if reg & 7 not in (4, 6):
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrad" if reg & 7 == 4 else "pslld", rm, ("i", value), 16)
        if two == 0x73 and opsize:
            reg, rm = modrm(True)
            if reg & 7 != 2:
                raise EvidenceError("unsupported vector shift at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("psrlq", rm, ("i", value), 16)
        if two == 0xAB:
            reg, rm = modrm()
            return finish("btsr", rm, ("r", reg), width)
        if two == 0xA3:
            reg, rm = modrm()
            return finish("btr", rm, ("r", reg), width)
        if two in (0xBE, 0xBF):
            reg, rm = modrm()
            return finish("movsx", ("r", reg), rm, width, cc=1 if two == 0xBE else 2)
        if two == 0xBA:
            reg, rm = modrm()
            if reg & 7 != 4:
                raise EvidenceError("unsupported bit test at %#x" % va)
            value = immediate(1) & 0xFF
            return finish("bt", rm, ("i", value), width)
        if two == 0x1F:
            modrm()
            return finish("nop")
        if two == 0x13:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and repne:
            reg, rm = modrm(True)
            if two == 0x10:
                return finish("movsd", ("x", reg), rm, 8)
            return finish("movsd", rm, ("x", reg), 8)
        if two in (0x10, 0x11) and rep:
            reg, rm = modrm(True)
            if rm[0] == "x":
                raise EvidenceError("movss between registers at %#x" % va)
            if two == 0x10:
                return finish("movss", ("x", reg), rm, 4)
            return finish("movss", rm, ("x", reg), 4)
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0xDF, True): "pandn", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x60, True): "punpcklbw",
                  (0x74, True): "pcmpeqb", (0x76, True): "pcmpeqd", (0x14, False): "punpckldq", (0x6C, True): "punpcklqdq",
                  (0xDB, True): "andpd", (0xEB, True): "orpd", (0x58, True): "addpd", (0x5E, True): "divpd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
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
        if two == 0xD6 and opsize:
            reg, rm = modrm(True)
            return finish("movq", rm, ("x", reg), 8)
        if two == 0x16 and not opsize:
            reg, rm = modrm(True)
            return finish("movhps", ("x", reg), rm, 8)
        if two == 0x12 and not opsize and not rep and not repne:
            reg, rm = modrm(True)
            return finish("movlps", ("x", reg), rm, 8)
        if two == 0x7E and opsize and not wide:
            reg, rm = modrm()
            return finish("movdout", rm, ("x", reg), 4)
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
            return finish("shrd", rm, ("r", reg), width, target=value)
        if two == 0xB1:
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), width)
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
        self.edges = set()
        self.steps = 0
        self.keep_rdx = False
        self.step_limit = STEP_LIMIT
        self.xmm_result = None

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
            return self.regs[operand[1]] >> 8 & 0xFF
        if kind == "i":
            return operand[1] & MASK[width]
        return self.memory.read(self.address(operand), width)

    def put(self, operand, width, value):
        value &= MASK[width]
        if operand[0] == "h":
            self.regs[operand[1]] = (self.regs[operand[1]] & ~0xFF00) | value << 8
            return
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

    def run(self, entry, args, stack=()):
        self.regs = [POISON] * 16
        for reg in CALLEE_SAVED:
            self.regs[reg] = 0x1111111111111100 + reg
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack):
            self.push(value)
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
            old_pc = pc
            pc = self.step(row)
            if row.op == "jcc":
                self.edges.add((old_pc, pc))
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
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            wanted = self.regs[RAX] & MASK[width]
            self.add_sub(wanted, current, 0, width, True)
            if wanted == current:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
        elif op == "xchg":
            first, second = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, second)
            self.put(row.b, width, first)
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
            return row.target
        elif op == "jmpi":
            target = self.get(row.a, 8)
            hook = self.slots.get(target)
            if hook:
                self.stub(hook)
                return self.pop()
            return target
        elif op == "pushm":
            self.push(self.get(row.a, 8))
        elif op == "pushi":
            self.push(row.a[1] & MASK[8])
        elif op == "btsr":
            bit = self.get(row.b, width) & (8 * width - 1)
            value = self.get(row.a, width)
            self.cf = bool(value >> bit & 1)
            self.put(row.a, width, value | 1 << bit)
        elif op == "btr":
            self.cf = bool(self.get(row.a, width) >> (self.get(row.b, width) & (8 * width - 1)) & 1)
        elif op == "movsx":
            value = self.get(row.b, row.cc)
            self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)
        elif op == "ror":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value >> count | value << (bits - count)) & MASK[width])
        elif op == "rol":
            bits = 8 * width
            count = row.b[1] % bits
            value = self.get(row.a, width)
            self.put(row.a, width, (value << count | value >> (bits - count)) & MASK[width])
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
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            left -= (left >> 63) << 64
            right -= (right >> 63) << 64
            product = left * right
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
            self.cf = self.of = not -(1 << 63) <= product < 1 << 63
        elif op == "mul":
            product = self.regs[RAX] * self.get(row.a, 8)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = product >> 64
            self.cf = self.of = self.regs[RDX] != 0
        elif op == "imul3":
            bits = 8 * width
            left, right = self.get(row.b, width), row.target & MASK[width]
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
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
        elif op == "xorps":
            self.xmm[row.a[1]] ^= self.vector(row.b)
        elif op == "int3":
            raise Halt("int3 at %#x" % row.va)
        elif op == "cwde":
            self.regs[RAX] = ((self.regs[RAX] & 0xFFFF) ^ 0x8000) - 0x8000 & MASK[4]
        elif op == "cdqe":
            self.regs[RAX] = (self.regs[RAX] & MASK[4]) | (MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)
        elif op == "imul2":
            bits = 8 * width
            left, right = self.get(row.a, width), self.get(row.b, width)
            left -= (left >> (bits - 1)) << bits
            right -= (right >> (bits - 1)) << bits
            product = left * right
            self.cf = self.of = not -SIGN[width] <= product < SIGN[width]
            self.put(row.a, width, product)
        elif op == "nop":
            pass
        elif op == "bswap":
            self.put(row.a, width, int.from_bytes(self.get(row.a, width).to_bytes(width, "little"), "big"))
        elif op == "bsr":
            source = self.get(row.b, width)
            if source == 0:
                raise Halt("bsr of zero at %#x" % row.va)
            self.put(row.a, width, source.bit_length() - 1)
        elif op in ("shld", "shrd"):
            count = (row.target if row.target is not None else self.regs[RCX]) & 63
            high, low = self.get(row.a, 8), self.get(row.b, 8)
            if op == "shld":
                value = (high << count | low >> (64 - count)) if count else high
            else:
                value = (high >> count | low << (64 - count)) if count else high
            self.put(row.a, 8, value)
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
        if op == "movss":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 4)
            else:
                self.memory.write(self.address(row.a), 4, self.xmm[row.b[1]] & MASK[4])
            return
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
                result = fdiv(left, right)
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
        elif op == "cvttsd2si":
            value = to_float(self.low(row.b))
            if value != value or not -9223372036854775808.0 <= value < 9223372036854775808.0:
                self.put(row.a, 8, 1 << 63)
            else:
                self.put(row.a, 8, int(value))
        elif op == "cvtsi2sd":
            value = self.get(row.b, 8)
            self.set_low(row.a[1], to_bits(float(value - (1 << 64) if value & SIGN[8] else value)))
        elif op == "andpd":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "orpd":
            self.xmm[row.a[1]] |= self.vector(row.b)
        elif op == "subpd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            low = to_float(left & MASK[8]) - to_float(right & MASK[8])
            high = to_float(left >> 64) - to_float(right >> 64)
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
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
        elif op == "movhps":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | self.get(row.b, 8) << 64
        elif op == "movlps":
            self.xmm[row.a[1]] = self.xmm[row.a[1]] >> 64 << 64 | self.get(row.b, 8)
        elif op == "movdout":
            self.put(row.a, 4, self.xmm[row.b[1]] & MASK[4])
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op in ("pslld", "psrad"):
            value, lanes = self.xmm[row.a[1]], 0
            for shift in (0, 32, 64, 96):
                lane = (value >> shift) & MASK[4]
                if op == "pslld":
                    lane = (lane << row.b[1]) & MASK[4]
                else:
                    lane = ((lane - (1 << 32) if lane & SIGN[4] else lane) >> row.b[1]) & MASK[4]
                lanes |= lane << shift
            self.xmm[row.a[1]] = lanes
        elif op == "pandn":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] ^ ((1 << 128) - 1)) & self.vector(row.b)
        elif op == "psrlq":
            value = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = ((value & MASK[8]) >> row.b[1]) | (((value >> 64) >> row.b[1]) << 64)
        elif op in ("addpd", "divpd"):
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            lanes = []
            for shift in (0, 64):
                one, two = to_float((left >> shift) & MASK[8]), to_float((right >> shift) & MASK[8])
                lanes.append(to_bits(one + two if op == "addpd" else fdiv(one, two)))
            self.xmm[row.a[1]] = lanes[0] | lanes[1] << 64
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
        elif op == "movmskpd":
            value = self.xmm[row.b[1]]
            self.put(row.a, 4, int(bool(value >> 63 & 1)) | int(bool(value >> 127 & 1)) << 1)
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")



# Only these six previously unselected windows are studied; earlier iterator
# bodies are modeled boundaries, not included in this selected set.
FUNCTIONS = {
    'inner_drop': 0x33f91a0,
    'user_book_drop': 0x33fa7b0,
    'member_book_drop': 0x33fbde0,
    'user_unwind_cleanup': 0x3378990,
    'member_unwind_cleanup': 0x3378360,
    'both_books_unwind': 0x37644c0,
}
ITERATORS = {0x33b5620: ('user', 24), 0x33af160: ('member', 32)}
FREE_SLOT = 0x576e010
FREE_HOOK = 0x7fff0010
CONTEXT = {
    'state_user_field_and_call': (0x3763d3b, '488dbb68010000e8696ac9ff'),
    'state_member_field_and_call': (0x3763d47, '488dbb80010000e88d80c9ff'),
    'state_unwind_both': (0x37641e5, '488dbb68010000e8cf020000'),
    'undelegate_user_result_drop': (0x3c0eb84, '48837c242000740a488d7c2428e80aa67eff'),
    'undelegate_member_result_drop': (0x3c0efcc, '48837c242000748c488d7c2430e8c2a17eff'),
}


def file_bytes(image, va, n, patches=None):
    if n <= 0:
        raise EvidenceError('range must be nonempty')
    matches = [s for s in image.sections if s['type'] != 8 and
               s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise EvidenceError('range is not uniquely file backed')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    raw = bytearray(image.blob[off:off+n])
    for at, value in (patches or {}).items():
        if va <= at < va+n:
            raw[at-va] = value
    return bytes(raw), off


def context_pins(image, patches=None):
    result = []
    for name, (va, expect) in CONTEXT.items():
        raw, off = file_bytes(image, va, len(bytes.fromhex(expect)), patches)
        if raw.hex() != expect:
            raise EvidenceError('changed context: ' + name)
        result.append((name, hex(va), hex(off), raw.hex()))
    return result


def lsda_records(image, start, patches=None):
    """Decode the observed LSDA call-site format; action payloads stay opaque."""
    fde = image.fde_records.get(start)
    if fde is None or fde['lsda'] is None:
        raise EvidenceError('selected function has no LSDA')
    sections = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(sections) != 1:
        raise EvidenceError('exception section missing or ambiguous')
    sec = sections[0]
    va = fde['lsda']
    if not sec['address'] <= va < sec['address']+sec['size']:
        raise EvidenceError('LSDA outside exception section')
    data = bytearray(image.blob[sec['offset']:sec['offset']+sec['size']])
    for at, value in (patches or {}).items():
        if sec['address'] <= at < sec['address']+sec['size']:
            data[at-sec['address']] = value
    pos = va-sec['address']
    if pos+2 > len(data) or data[pos] != 0xff:
        raise EvidenceError('unsupported LSDA landing-pad encoding')
    type_enc = data[pos+1]
    pos += 2
    if type_enc == 0x9b:
        type_offset, pos = uleb(data, pos, len(data))
        if pos + type_offset > len(data):
            raise EvidenceError('LSDA type table outside exception section')
    elif type_enc == 0xff:
        type_offset = None
    else:
        raise EvidenceError('unsupported LSDA type encoding')
    if pos >= len(data) or data[pos] != 1:
        raise EvidenceError('unsupported LSDA call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, len(data))
    end = pos+length
    if end > len(data):
        raise EvidenceError('LSDA call-site table outside section')
    header_end = pos
    result, prev = [], start
    while pos < end:
        at = pos
        begin_offset, pos = uleb(data, pos, end)
        span, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        begin, finish = start+begin_offset, start+begin_offset+span
        target = start+landing if landing else None
        if not start <= begin <= finish <= fde['end'] or begin < prev:
            raise EvidenceError('invalid LSDA call-site range')
        if target is not None and not start <= target < fde['end']:
            raise EvidenceError('LSDA landing outside FDE')
        result.append((sec['address']+at, bytes(data[at:pos]), begin, finish, target, action))
        prev = finish
    if pos != end:
        raise EvidenceError('LSDA table overrun')
    return {'va': va, 'header': bytes(data[va-sec['address']:header_end]),
            'type_encoding': type_enc, 'type_offset': type_offset, 'records': result}


class DropMachine(Machine):
    def step(self, row):
        start, end = self.image.fde(row.va)
        if start not in FUNCTIONS.values() or row.next > end:
            raise Halt('instruction leaves selected FDE')
        return super().step(row)


class DropFixture:
    """Finite synthetic node graphs, independent from the byte interpreter."""
    def __init__(self, image, patches=None):
        self.machine = DropMachine(image, patches)
        self.machine.real = frozenset(FUNCTIONS.values())
        if patches:
            self.machine.step_limit = 20000
        self.mem = self.machine.memory
        self.next_addr = HEAP_BASE + 0x10000
        self.live = {}
        self.frozen = {}
        self.events = []
        self.expected = []
        self.routes = {}
        self.row_events = {}
        self.positions = {}
        self.calls = []
        self.mem.statics[FREE_SLOT] = FREE_HOOK
        self.machine.slots[FREE_HOOK] = self.free
        for entry, (name, width) in ITERATORS.items():
            self.machine.calls[entry] = self.iterator(name, width)

    def alloc(self, size):
        addr = self.next_addr
        self.next_addr += (size + 15) & ~15
        if self.next_addr >= HEAP_BASE + HEAP_SIZE:
            raise Halt('fixture arena exhausted')
        self.mem.put_bytes(addr, bytes(size))
        return addr

    def node(self, tree, parent=0, edge=0):
        # Tree is (leaf_count, children); internal count is len(children)-1.
        count, children = tree
        if children and count != len(children)-1:
            raise ValueError('invalid synthetic tree')
        if not 0 <= count <= 11:
            raise ValueError('invalid node count')
        height = 0 if not children else 1 + self.depth(children[0])
        if any(self.depth(child) != height-1 for child in children):
            raise ValueError('unbalanced synthetic tree')
        addr = self.alloc(0x250 if children else 0x1f0)
        size = 0x250 if children else 0x1f0
        self.live[addr] = size
        self.mem.write(addr, 8, parent)
        self.mem.write(addr+0x1ec, 2, edge)
        self.mem.write(addr+0x1ee, 2, count)
        total = count
        descendants = []
        for i, child in enumerate(children):
            child_addr, child_total, child_events = self.node(child, addr, i)
            self.mem.write(addr+0x1f0+8*i, 8, child_addr)
            total += child_total
            descendants.extend(child_events)
        descendants.append((addr, size, 0))
        return addr, total, descendants

    @staticmethod
    def depth(tree):
        return 0 if not tree[1] else 1+DropFixture.depth(tree[1][0])

    def descriptor(self, addr, tree):
        if tree is None:
            self.mem.put_bytes(addr, bytes(24))
            return []
        root, count, expected = self.node(tree)
        self.mem.write(addr, 8, root)
        self.mem.write(addr+8, 8, self.depth(tree))
        self.mem.write(addr+16, 8, count)
        return expected

    def snapshot_nodes(self):
        self.frozen = {addr: self.mem.bytes_at(addr, size) for addr, size in self.live.items()}
        return self.frozen

    def check_unchanged_nodes(self, before):
        for addr, expected in before.items():
            if self.mem.bytes_at(addr, len(expected)) != expected:
                raise Halt('tree bytes changed before modeled deallocation')

    def free(self, m):
        addr, size, align = (m.regs[x] for x in (RDI, RSI, RDX))
        if self.live.get(addr) != size or align != 0:
            raise Halt('unexpected or duplicate free')
        if addr in self.frozen and self.mem.bytes_at(addr, size) != self.frozen[addr]:
            raise Halt('tree bytes changed before modeled deallocation')
        del self.live[addr]
        self.events.append((addr, size, align))
        m.regs[RAX] = 0

    def iterator(self, kind, width):
        def hook(m):
            out, it = m.regs[RDI], m.regs[RSI]
            root = self.mem.read(it+16, 8) if self.mem.read(it, 8) else 0
            if root == 0:
                self.mem.write(out, 8, 0)
                self.calls.append((kind, 'end'))
                return
            if (kind, root) not in self.routes:
                raise Halt('unexpected outer iterator root')
            seq = self.routes[kind, root]
            pos = self.positions.get((kind, root), 0)
            if pos < len(seq):
                node, index = seq[pos]
                self.mem.write(out, 8, node)
                self.mem.write(out+8, 8, 0)
                self.mem.write(out+16, 8, index)
                self.positions[kind, root] = pos+1
                self.calls.append((kind, pos))
            else:
                self.mem.write(out, 8, 0)
                self.calls.append((kind, 'end'))
        return hook

    def book(self, descriptor, kind, trees):
        # Iterator hooks return a synthetic node and row index. They do not
        # implement or claim the original outer-tree traversal or its frees.
        if trees is None:
            self.mem.put_bytes(descriptor, bytes(24))
            return []
        width = 24 if kind == 'user' else 32
        node = self.alloc(8 + width*len(trees) + 24)
        self.mem.write(descriptor, 8, node)
        self.mem.write(descriptor+8, 8, 0)
        self.mem.write(descriptor+16, 8, len(trees))
        seq, expected = [], []
        for i, tree in enumerate(trees):
            row_events = self.descriptor(node+8+width*i, tree)
            self.row_events[kind, node, i] = row_events
            expected.extend(row_events)
            seq.append((node, i))
        self.routes[kind,node] = seq
        return expected


def leaf(n):
    return (n, ())


def full_tree(depth, count):
    if depth == 0:
        return leaf(count)
    return (count, tuple(full_tree(depth-1, count) for _ in range(count+1)))


def run_inner(image, tree, patches=None, *, length_override=None):
    h = DropFixture(image, patches)
    desc = h.alloc(24)
    expected = h.descriptor(desc, tree)
    if length_override is not None:
        h.mem.write(desc+16, 8, length_override)
    before = h.snapshot_nodes()
    h.machine.run(FUNCTIONS['inner_drop'], {RDI: desc})
    h.check_unchanged_nodes(before)
    if length_override is None and (h.events != expected or h.live):
        raise Halt('inner drop differs from independent postorder')
    return h


def run_books(image, users, members, patches=None, mode="normal"):
    h = DropFixture(image, patches)
    descriptor = h.alloc(48)
    expected = h.book(descriptor, 'user', users)
    expected += h.book(descriptor+24, 'member', members)
    before = h.snapshot_nodes()
    if mode == 'normal':
        h.machine.run(FUNCTIONS['user_book_drop'], {RDI: descriptor})
        h.machine.run(FUNCTIONS['member_book_drop'], {RDI: descriptor+24})
    elif mode == 'unwind':
        h.machine.run(FUNCTIONS['both_books_unwind'], {RDI: descriptor})
    else:
        raise ValueError('unknown drop entry')
    h.check_unchanged_nodes(before)
    if h.events != expected or h.live:
        raise Halt('book drop differs from independent postorder')
    return h


def run_cleanup(image, kind, trees, consumed=0, patches=None):
    if not 0 <= consumed <= len(trees):
        raise ValueError('invalid consumed count')
    h = DropFixture(image, patches)
    desc = h.alloc(24)
    h.book(desc, kind, trees)
    root = h.mem.read(desc, 8)
    width = 24 if kind == 'user' else 32
    for i in range(consumed):
        h.machine.run(FUNCTIONS['inner_drop'], {RDI: root+8+width*i})
    h.events.clear()
    h.positions[kind,root] = consumed
    expected = [event for i in range(consumed, len(trees))
                for event in h.row_events[kind,root,i]]
    it = h.alloc(72)
    h.mem.write(it, 8, 1)
    h.mem.write(it+16, 8, root)
    entry = FUNCTIONS['user_unwind_cleanup' if kind == 'user' else 'member_unwind_cleanup']
    before = h.snapshot_nodes()
    h.machine.run(entry, {RDI: it})
    h.check_unchanged_nodes(before)
    if h.events != expected or h.live:
        raise Halt('cleanup differs from independent suffix postorder')
    return h


def uniform_tree(depth, inner, leaf_count):
    if depth == 0:
        return leaf(leaf_count)
    return (inner, tuple(uniform_tree(depth-1, inner, leaf_count)
                         for _ in range(inner+1)))


def broken_parent(image, patches=None):
    h = DropFixture(image, patches)
    desc = h.alloc(24)
    h.descriptor(desc, uniform_tree(1, 1, 5))
    root = h.mem.read(desc, 8)
    child = h.mem.read(root+0x1f0, 8)
    h.mem.write(child, 8, 0)
    h.mem.statics[0x576e470] = 0x7fff0470
    def panic(m):
        raise Panicked('panic boundary')
    h.machine.slots[0x7fff0470] = panic
    try:
        h.machine.run(FUNCTIONS['inner_drop'], {RDI: desc})
    except Panicked:
        if 0x33f94e3 not in h.machine.seen or len(h.events) != 1:
            raise Halt('wrong corrupt-parent boundary')
        return h
    raise Halt('corrupt parent did not reach panic boundary')


class Resumed(Exception):
    pass


class DoubleUnwind(Exception):
    pass


class LandingMachine(DropMachine):
    """Inject synthetic exceptions at reviewed call sites, then enter their LSDA landing."""
    def __init__(self, image, injections):
        super().__init__(image)
        self.injections = injections
        self.injected = []

    def step(self, row):
        if row.va in self.injections:
            if row.op != 'call':
                raise Halt('injection site is no longer a direct call')
            self.regs[RAX] = 0x12345678
            self.injected.append(row.va)
            return self.injections[row.va]
        return super().step(row)


def run_landing(image, kind):
    h = DropFixture(image)
    cases = {
        'user': (0x33fa841, 0x33fa863, 0x33fa7b0),
        'member': (0x33fbe71, 0x33fbe93, 0x33fbde0),
        'both': (0x37644c7, 0x37644df, 0x37644c0),
        'double': (0x37644c7, 0x37644df, 0x37644c0),
    }
    if kind not in cases:
        raise ValueError('unknown landing fixture')
    fail, landing, entry = cases[kind]
    injections = {fail: landing}
    if kind == 'double':
        injections[0x37644e9] = 0x37644f6
    for site, target in injections.items():
        start, _ = image.fde(site)
        matches = [r for r in lsda_records(image, start)['records']
                   if r[2] <= site < r[3] and r[4] == target]
        if len(matches) != 1:
            raise EvidenceError('injection does not match one LSDA record')
    machine = LandingMachine(image, injections)
    machine.memory = h.mem
    machine.real = frozenset(FUNCTIONS.values())
    machine.calls = h.machine.calls.copy()
    machine.slots = h.machine.slots.copy()
    h.machine = machine
    h.mem.statics[0x576e128] = 0x7fff0128
    def resume(m):
        if m.regs[RDI] != 0x12345678:
            raise Halt('exception object changed before resume')
        raise Resumed('resume boundary')
    def double(m):
        raise DoubleUnwind('double unwind boundary')
    machine.calls[0x5660110] = resume
    machine.slots[0x7fff0128] = double
    desc = h.alloc(48)
    if kind in ('user','member'):
        trees = [None, leaf(5), uniform_tree(1,5,5)]
        expected = h.book(desc, kind, trees)
        entry_arg = desc
    else:
        h.book(desc, 'user', None)
        expected = h.book(desc+24, 'member', [leaf(5), uniform_tree(1,5,5)])
        entry_arg = desc
    before = h.snapshot_nodes()
    outcome = ''
    try:
        machine.run(entry, {RDI: entry_arg})
    except Resumed:
        outcome = 'resume'
    except DoubleUnwind:
        outcome = 'double_unwind'
    h.check_unchanged_nodes(before)
    expected_outcome = 'double_unwind' if kind == 'double' else 'resume'
    if outcome != expected_outcome or machine.injected != list(injections):
        raise Halt('wrong modeled landing boundary')
    if kind != 'double' and (h.events != expected or h.live):
        raise Halt('landing cleanup differs from expected suffix')
    if kind == 'double' and h.events:
        raise Halt('unexpected free before double-unwind boundary')
    return h, outcome


def run_mutation(image, name):
    choices = {
        'root_condition': (0x33f91b2, 1),
        'free_size_choice': (0x33f92f2, 1),
        'user_stride': (0x33fa838, 0x40),
        'member_stride': (0x33fbe68, 1),
        'second_book_offset': (0x37644cf, 8),
    }
    va, mask = choices[name]
    original = file_bytes(image, va, 1)[0][0]
    patch = {va: original ^ mask}
    def invoke(patches):
        if name == 'root_condition':
            return run_inner(image, leaf(5), patches)
        if name == 'free_size_choice':
            return run_inner(image, uniform_tree(1, 5, 5), patches)
        if name == 'user_stride':
            return run_books(image, [leaf(2), leaf(3)], None, patches)
        if name == 'member_stride':
            return run_books(image, None, [leaf(2), leaf(3)], patches)
        return run_books(image, [leaf(2)], [leaf(3)], patches, mode='unwind')
    invoke(None)
    try:
        invoke(patch)
    except (Halt, EvidenceError) as exc:
        return (name, hex(va), f'{original:02x}', f'{original ^ mask:02x}', type(exc).__name__, str(exc))
    raise EvidenceError('mutation survived: ' + name)


def conditional_mutations(image, all_rows):
    """Invert each branch on up to two reaching fixtures; faults are separate."""
    candidates = []
    def add(label, call):
        baseline = call(None)
        candidates.append((label, call, frozenset(baseline.machine.seen)))
    add('null_root', lambda p: run_inner(image, None, p))
    for n in (0, 1, 5, 11):
        add('leaf_%d' % n, lambda p,n=n: run_inner(image, leaf(n), p))
    for height, count in ((1,1),(1,5),(1,11),(2,1),(2,5),(3,1)):
        add('tree_%d_%d' % (height,count),
            lambda p,h=height,n=count: run_inner(image, uniform_tree(h,n,5), p))
    for depth in (7,8,9,15,16,17):
        chain = leaf(5)
        empty = leaf(0)
        for _ in range(depth):
            chain = (0, (chain,))
            empty = (0, (empty,))
        add('chain_%d' % depth, lambda p,t=chain: run_inner(image, t, p))
        add('empty_chain_%d' % depth, lambda p,t=empty: run_inner(image, t, p))
        if depth in (7,8,15,16):
            tree = (1, (chain, chain))
            add('fork_%d' % depth, lambda p,t=tree: run_inner(image, t, p))
    add('both_nonempty', lambda p: run_books(image,
        [leaf(5), uniform_tree(1,5,5)], [leaf(6), leaf(11)], p, mode='unwind'))
    add('both_empty', lambda p: run_books(image, None, None, p, mode='unwind'))
    for kind in ('user','member'):
        for consumed in (0,1,3):
            add('cleanup_%s_%d' % (kind,consumed),
                lambda p,k=kind,n=consumed: run_cleanup(image,k,[leaf(5),leaf(6),leaf(11)],n,p))
    add('broken_parent', lambda p: broken_parent(image, p))
    controls = []
    for name, rows in all_rows.items():
        for row in rows:
            if row.op != 'jcc':
                continue
            raw, _ = file_bytes(image, row.va, row.size)
            byte_va = row.va+1 if raw[0] == 0x0f else row.va
            old = file_bytes(image, byte_va, 1)[0][0]
            if not (0x70 <= old <= 0x7f or 0x80 <= old <= 0x8f):
                raise EvidenceError('unsupported conditional opcode')
            reaching = [(label, call) for label, call, seen in candidates if row.va in seen][:2]
            outcomes = []
            for label, call in reaching:
                try:
                    call({byte_va: old ^ 1})
                    outcomes.append((label,'survived'))
                except (Halt, EvidenceError, Panicked) as exc:
                    message = str(exc)
                    observed = ('differs from' in message or 'unexpected or duplicate free' in message
                                or 'tree bytes changed' in message)
                    outcomes.append((label, 'observable_difference' if observed else 'interpreter_or_hook_fault'))
            kinds = [outcome for _,outcome in outcomes]
            result = ('observable_difference' if 'observable_difference' in kinds else
                      'interpreter_or_hook_fault' if 'interpreter_or_hook_fault' in kinds else
                      'survived' if kinds else 'no_witness')
            controls.append((name, hex(row.va), hex(byte_va), f'{old:02x}', f'{old^1:02x}',
                             result, ','.join(label+':'+outcome for label,outcome in outcomes)))
    return controls


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(image, out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    context = context_pins(image)
    all_rows, function_rows = {}, []
    for name, start in FUNCTIONS.items():
        _, end = image.exact_fde(start)
        raw, off = file_bytes(image, start, end-start)
        sec = [s for s in image.sections if s['type'] != 8 and s['flags'] & 4
               and s['address'] <= start and end <= s['address']+s['size']]
        if len(sec) != 1:
            raise EvidenceError('selected FDE not uniquely executable and file backed')
        rows = decode_range(image, start, end)
        starts = {r.va for r in rows}
        for r in rows:
            if r.op in ('jmp', 'jcc') and start <= r.target < end and r.target not in starts:
                raise EvidenceError('intra-FDE transfer does not land on decoded row')
        all_rows[name] = rows
        fde = image.fde_records[start]
        function_rows.append((name, hex(start), hex(end), hex(off), len(raw),
                              hex(fde['fde']), hex(fde['cie']),
                              hex(fde['lsda']) if fde['lsda'] else '',
                              hashlib.sha256(raw).hexdigest(), len(rows)))
    lsda_rows = []
    for name, start in FUNCTIONS.items():
        if image.fde_records[start]['lsda'] is None:
            continue
        lsda = lsda_records(image, start)
        instruction_starts = {r.va for r in all_rows[name]}
        for va, raw, begin, end, landing, action in lsda['records']:
            if landing is not None and landing not in instruction_starts:
                raise EvidenceError('LSDA landing is not a decoded instruction start')
            lsda_rows.append((name, hex(lsda['va']), lsda['header'].hex(), hex(va),
                              raw.hex(), hex(begin), hex(end),
                              hex(landing) if landing is not None else '', action))
    instruction_rows, transfer_rows = [], []
    for name, rows in all_rows.items():
        for r in rows:
            raw, off = file_bytes(image, r.va, r.size)
            target = hex(r.target) if isinstance(r.target, int) and r.op in ('call', 'jmp', 'jcc') else ''
            instruction_rows.append((name, hex(r.va), hex(off), r.size, raw.hex(), r.op, target))
            if r.op in ('call', 'calli', 'jmp', 'jmpi', 'jcc'):
                slot = ''
                if r.op in ('calli', 'jmpi') and r.a and r.a[0] == 'm' and r.a[1] is None and r.a[2] is None:
                    slot = hex(r.a[4])
                transfer_rows.append((name, hex(r.va), raw.hex(), r.op, target, slot,
                                      hex(r.next) if r.op == 'jcc' else ''))
    observed = collections.defaultdict(set)
    seen = set()
    cases = []
    witnesses = []
    def record(name, h, kind):
        seen.update(h.machine.seen)
        for site, dest in h.machine.edges:
            observed[site].add(dest)
        if name in ('height2_01_leaf_05', 'books_4_5_normal', 'books_4_5_unwind', 'cleanup_user_1', 'cleanup_member_1'):
            witnesses.extend((name, i, hex(a-HEAP_BASE), size, align)
                             for i, (a,size,align) in enumerate(h.events))
        packed = b''.join(struct.pack('<QQQ', a-HEAP_BASE, s, z) for a,s,z in h.events)
        cases.append((name, kind, len(h.events), sum(s == 0x1f0 for _,s,_ in h.events),
                      sum(s == 0x250 for _,s,_ in h.events), len(h.calls), h.machine.steps,
                      hashlib.sha256(packed).hexdigest()))
    record('null_root', run_inner(image, None), 'inner')
    for n in range(12):
        record('leaf_%02d' % n, run_inner(image, leaf(n)), 'inner')
    for n in range(1, 12):
        for leaf_n in (1, 5, 11):
            record('height1_%02d_leaf_%02d' % (n, leaf_n),
                   run_inner(image, uniform_tree(1, n, leaf_n)),
                   'inner' if leaf_n >= 5 else 'inner_corrupt_shape')
    for n in (1, 2, 5, 8):
        for leaf_n in (1, 5, 11):
            record('height2_%02d_leaf_%02d' % (n, leaf_n),
                   run_inner(image, uniform_tree(2, n, leaf_n)),
                   'inner' if n >= 5 and leaf_n >= 5 else 'inner_corrupt_shape')
    for n in (1, 5):
        record('height3_%02d' % n, run_inner(image, uniform_tree(3, n, 5)),
               'inner' if n >= 5 else 'inner_corrupt_shape')
    for depth in (7, 8, 9, 16, 17):
        chain = leaf(5)
        for _ in range(depth):
            chain = (0, (chain,))
        record('noncanonical_chain_%02d' % depth, run_inner(image, chain), 'inner_corrupt_shape')
    for depth in (1, 7, 8, 9, 16):
        chain = leaf(0)
        for _ in range(depth):
            chain = (0, (chain,))
        record('noncanonical_empty_chain_%02d' % depth, run_inner(image, chain), 'inner_corrupt_shape')
    for depth in (7, 8, 15, 16):
        chain = leaf(5)
        for _ in range(depth):
            chain = (0, (chain,))
        record('noncanonical_fork_%02d' % depth, run_inner(image, (1, (chain, chain))), 'inner_corrupt_shape')
    for parent_count in (1, 5, 10, 11):
        for left_count in (5, 6, 11):
            for right_count in (5, 6, 11):
                counts = [left_count] + [5]*(parent_count-1) + [right_count]
                tree = (parent_count, tuple(leaf(n) for n in counts))
                record('uneven_h1_%02d_%02d_%02d' % (parent_count, left_count, right_count),
                       run_inner(image, tree), 'inner')
    for left_count in (5, 6, 11):
        for right_count in (5, 6, 11):
            left = uniform_tree(1, left_count, 5)
            right = uniform_tree(1, right_count, 11)
            record('uneven_h2_%02d_%02d' % (left_count, right_count),
                   run_inner(image, (1, (left, right))), 'inner')
    mixed1 = (2, (leaf(5), leaf(6), leaf(11)))
    mixed2 = (1, ((5, tuple(leaf(n) for n in (5,6,7,8,9,10))),
                  (6, tuple(leaf(n) for n in (11,10,9,8,7,6,5)))))
    record('mixed_height1', run_inner(image, mixed1), 'inner')
    record('mixed_height2', run_inner(image, mixed2), 'inner')
    tree_options = (None, [], [None], [leaf(5)], [leaf(3), uniform_tree(1, 5, 5)],
                    [uniform_tree(2, 2, 5), leaf(11), None])
    for i, users in enumerate(tree_options):
        for j, members in enumerate(tree_options):
            for mode in ('normal', 'unwind'):
                record('books_%d_%d_%s' % (i,j,mode), run_books(image, users, members, mode=mode), mode)
    cleanup_trees = [leaf(5), uniform_tree(1, 5, 5), leaf(11)]
    for kind in ('user', 'member'):
        for consumed in range(4):
            record('cleanup_%s_%d' % (kind, consumed),
                   run_cleanup(image, kind, cleanup_trees, consumed), 'cleanup')
    stale = run_inner(image, None, length_override=9)
    if stale.events:
        raise Halt('null root with stale length reached free')
    seen.update(stale.machine.seen)
    for site, dest in stale.machine.edges:
        observed[site].add(dest)
    bad = broken_parent(image)
    seen.update(bad.machine.seen)
    for site, dest in bad.machine.edges:
        observed[site].add(dest)
    landing_cases = []
    for kind in ('user', 'member', 'both', 'double'):
        landed, outcome = run_landing(image, kind)
        seen.update(landed.machine.seen)
        for site, dest in landed.machine.edges:
            observed[site].add(dest)
        landing_cases.append((kind, ','.join(hex(x) for x in landed.machine.injected),
                              outcome, len(landed.events), len(landed.calls)))
    mutations = [run_mutation(image, name) for name in
                 ('root_condition','free_size_choice','user_stride','member_stride','second_book_offset')]
    branch_edits = conditional_mutations(image, all_rows)
    branch_rows = []
    for name, rows in all_rows.items():
        for r in rows:
            if r.op == 'jcc':
                branch_rows.append((name, hex(r.va), r.cc, hex(r.target), hex(r.next),
                                    int(r.target in observed[r.va]), int(r.next in observed[r.va])))
    slot_names = {FREE_SLOT: 'deallocation boundary', 0x576e470: 'panic boundary',
                  0x576e128: 'double-unwind boundary'}
    reloc = []
    for slot in sorted(slot_names):
        matches = [(kind, addend, symbol) for pos,kind,addend,symbol in image.relocations() if pos == slot]
        if len(matches) != 1:
            raise EvidenceError('missing or ambiguous relocation')
        kind, addend, sym = matches[0]
        reloc.append((slot_names[slot],hex(slot),kind,hex(addend),sym))
    write_tsv(out/'functions.tsv', ('role','start_va','end_va','file_offset','bytes','fde_va','cie_va','lsda_va','sha256','decoded_rows'), function_rows)
    write_tsv(out/'instructions.tsv', ('role','va','file_offset','size','bytes','operation','direct_target'), instruction_rows)
    write_tsv(out/'transfers.tsv', ('role','va','bytes','operation','direct_target','rip_slot','fallthrough'), transfer_rows)
    write_tsv(out/'branches.tsv', ('role','va','condition_code','taken_va','fallthrough_va','taken_seen','fallthrough_seen'), branch_rows)
    write_tsv(out/'lsda.tsv', ('role','lsda_va','header_bytes','record_va','record_bytes','start_va','end_va','landing_va','action'), lsda_rows)
    write_tsv(out/'context.tsv', ('name','va','file_offset','bytes'), context)
    write_tsv(out/'relocations.tsv', ('boundary','slot_va','type','addend','symbol_index'), reloc)
    write_tsv(out/'cases.tsv', ('name','kind','free_calls','leaf_frees','internal_frees','iterator_calls','steps','free_event_sha256'), cases)
    write_tsv(out/'witnesses.tsv', ('case','order','fixture_address_offset','size','third_argument'), witnesses)
    write_tsv(out/'landing-cases.tsv', ('case','injected_call_sites','terminal_hook','free_calls','iterator_calls'), landing_cases)
    write_tsv(out/'branch-mutations.tsv', ('role','branch_va','opcode_va','original','mutant','result','fixtures'), branch_edits)
    write_tsv(out/'mutations.tsv', ('name','va','original','mutant','detection','detail'), mutations)
    write_tsv(out/'corruption.tsv', ('case','boundary_va','free_calls_before_boundary','observation'),
              [('missing_parent','0x33f94e3',len(bad.events),'panic hook reached after leaf free'),
               ('null_root_stale_length','0x33f93bb',len(stale.events),'returns without a free')])
    summary = {
        'target_sha256': SHA256,
        'selected_fdes': len(FUNCTIONS),
        'selected_bytes': sum(row[4] for row in function_rows),
        'decoded_instructions': len(instruction_rows),
        'reached_instructions': sum(r.va in seen for rows in all_rows.values() for r in rows),
        'lsda_call_site_records': len(lsda_rows),
        'conditional_sites': len(branch_rows),
        'conditional_both_edges_seen': sum(a == 1 and b == 1 for *_, a,b in branch_rows),
        'conditional_unreached': sum(a == 0 and b == 0 for *_, a,b in branch_rows),
        'synthetic_cases': len(cases),
        'noncanonical_shape_cases': sum(row[1] == 'inner_corrupt_shape' for row in cases),
        'corruption_controls': 2,
        'modeled_landing_cases': len(landing_cases),
        'targeted_mutations_detected': len(mutations),
        'branch_mutations': len(branch_edits),
        'branch_mutation_results': dict(sorted(collections.Counter(row[5] for row in branch_edits).items())),
        'limitations': 'Finite synthetic fixtures and modeled outer iterator, deallocation and panic boundaries; no target execution or Rust equivalence.',
    }
    (out/'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n', encoding='utf8')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True)
    args = p.parse_args()
    image = load_image()
    result = generate(image, args.out)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, Halt, ValueError, OSError, struct.error) as exc:
        print('staking_delegation_drop94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
