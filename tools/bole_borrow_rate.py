#!/usr/bin/env python3
"""Pin node #94 BOLE token arithmetic: utilization, the kinked borrow rate and the token info row.

0x3741520 and 0x37412a0 turn a token record into a two slope rate in 1e14 units, as f64 and as rate/1e10.
0x3741010 and 0x3741160 give the utilization as a Result. 0x2a32d40 and 0x2a290f0 build the info row with
borrowYearlyRate, supplyYearlyRate and the totals. The real bytes run under recording
stubs, a separately written rule list predicts every run including every 128 bit divide request, and every
reached conditional row, immediate and field offset is mutated. No objdump or readelf output is parsed and the
binary is never executed. Standard library only.

    python3 tools/bole_borrow_rate.py --out <dir>
"""

import argparse
import bisect
import collections
import fractions
import hashlib
import json
import math
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
HEAP_SIZE = 0x20000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000
MUTANT_STEP_LIMIT = 20000


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

    def relative(self):
        if self.relative_map is None:
            self.relative_map = {slot: addend for slot, kind, addend, _ in self.relocations() if kind == 8}
        return self.relative_map

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate or std root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        for marker in ("/l1/", "/library/"):
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
        if kind in (2, 3, 4, 6):
            return finish({2: "not", 3: "neg", 4: "mul", 6: "div"}[kind], rm, w=w)
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
        elif op == "punpcklqdq":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
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


def fdiv(left, right):
    if right == 0:
        if left == 0 or left != left:
            return math.nan
        return math.copysign(math.inf, math.copysign(1.0, left) * math.copysign(1.0, right))
    return left / right


RATE = 0x3741520
RATE_INT = 0x37412A0
UTIL_WORD = 0x3741010
UTIL_F64 = 0x3741160
INFO = 0x2A32D40
TOTALS = 0x2A290F0
TARGETS = (RATE, RATE_INT, UTIL_WORD, UTIL_F64, INFO, TOTALS)
NAMES = {RATE: "rate_f64", RATE_INT: "rate_e10", UTIL_WORD: "utilization_e10", UTIL_F64: "utilization_f64", INFO: "token_info_row", TOTALS: "token_totals"}

SLOT_DIV = 0x576E1A8
SLOT_RATE = 0x5774B68
SLOT_UNWRAP = 0x576E470
SLOT_INDEX = 0x576DFC8
SLOT_OVERFLOW = 0x576E150
SLOT_UTIL_F64 = 0x5775520
SLOT_INFO = 0x5774F28
MARK_BASE = 0x7700000000

E14 = 10 ** 14
E10 = 10 ** 10
TOP = MASK[8]
TOP128 = (1 << 128) - 1
GUARD = E14 << 64
EDGE_LEFT = 3 * 13 * 7021362262547
EDGE_RIGHT = 2039 * 1058093 * 3122429689
TAG_OK = 0x186
MUL_RATE = 0xDBE6FECEBDEDD5BF
SHIFT_RATE = 97
MUL_UTIL = 0x6DF37F675EF7
SHIFT_UTIL = 80
KEY_ADDR = 0x209310
SERDE_FN = 0x1E85A90
MIN_WORD = 0x657461725F6E696D
MAX_STEP = 0x9F800
WRITE_SITE = 0x3741C4C
WRITE_BYTES = "4a8d04334883c0d0488b4c24480f10010f1049100f1148100f1100"
INFO_SERIALIZER = 0x2A35B60
F_E14 = 0x20A810
F_ONE = 0x20A730
TABLE_TOKEN = 0x584B08
TABLE_PRICE = 0x4213B8

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x60
OWNER = HEAP_BASE + 0x300
META = HEAP_BASE + 0x400
SPOTS = HEAP_BASE + 0x800
SPOT_STRIDE = 0x20
TOKENS = HEAP_BASE + 0xA00
TOKEN_STRIDE = 0xE8
LISTS = HEAP_BASE + 0xF80
REC = HEAP_BASE + 0x1000
NODES = HEAP_BASE + 0x1200
NODE_STRIDE = 0x900
USED = 0x6000
FILL = 0xCC
REC_SIZE = 0xB0
VAL_LEN = 0x7F2
KEY_AT = 0x798
EDGE_AT = 0x7F8


class Case:
    __slots__ = ("name", "kind", "rec", "faults", "tok", "f", "tokens", "spots", "lists", "shape", "n_tokens")

    def __init__(self, name, kind, rec=None, faults=None, tok=0, f=0, tokens=None, spots=(), lists=None, shape="leaf", n_tokens=None):
        self.name, self.kind, self.rec, self.faults = name, kind, rec, faults or {}
        self.tok, self.f, self.tokens, self.spots, self.lists, self.shape, self.n_tokens = tok, f, tokens, spots, lists or {}, shape, n_tokens


def record(a=0, ia=E14, b=0, ib=E14, mn=0, mx=E14, kr=5 * 10 ** 12, k=8 * 10 ** 13, ltv=None, px=0, bal=0):
    return dict(a=a, ia=ia, b=b, ib=ib, mn=mn, mx=mx, kr=kr, k=k, ltv=ltv, px=px, bal=bal)


class Div:
    """The model's 128 bit divide: logs every request and answers an injected quotient when a case asks."""

    def __init__(self, faults):
        self.log, self.faults = [], faults

    def __call__(self, num, den):
        index = len(self.log)
        self.log.append((num, den))
        if index in self.faults:
            return self.faults[index]
        return num // den


def low(value):
    return value & TOP


def high(value):
    return value >> 64


def ceil_total(a, ia, div):
    product = a * ia
    q = div(product, E14)
    rem = (product - q * E14) & TOP128
    return (q + (1 if rem else 0)) & TOP128


def ratio_or_zero(rec, div):
    a, ia, b, ib = rec["a"], rec["ia"], rec["b"], rec["ib"]
    total = ceil_total(a, ia, div)
    product = b * ib
    if high(product) > E14 - 1:
        return 0
    supplied = div(product, E14)
    if low(supplied) == 0 or high(total) or (a == 0 and low(total)):
        return 0
    if b == 0:
        return 0
    q = div(low(total) * E14, supplied)
    return 0 if high(q) else min(low(q), E14)


def curve(rec, u, div):
    bend, k = rec["kr"], rec["k"]
    if u == k:
        return bend
    if u > k:
        top = rec["mx"]
        if k > E14 - 1:
            return top
        f = div(((u - k) & TOP) * E14, E14 - k)
        if top < bend or high(f):
            return top
        product = low(f) * (top - bend)
        if product >= GUARD:
            return top
        value = low(div(product, E14)) + bend
        return top if value > TOP else value
    floor_rate = rec["mn"]
    f = div(u * E14, k)
    if bend < floor_rate or high(f):
        return bend
    product = low(f) * (bend - floor_rate)
    if product >= GUARD:
        return bend
    value = low(div(product, E14)) + floor_rate
    return bend if value > TOP else value


def util_result(rec, div):
    a, ia, b, ib = rec["a"], rec["ia"], rec["b"], rec["ib"]
    total = ceil_total(a, ia, div)
    err = 3 if high(total) else 2 if a == 0 and low(total) else None
    product = b * ib
    if high(product) > E14 - 1:
        return (1, err or 3)
    supplied = div(product, E14)
    if b == 0 and low(supplied):
        return (1, err or 2)
    if err:
        return (1, err)
    if low(supplied) == 0:
        return (0, 0)
    q = div(low(total) * E14, supplied)
    if high(q):
        return (1, 3)
    return (0, min(low(q), E14))


def result_bytes(base, outcome, word):
    data = bytearray(base)
    if outcome[0]:
        data[0], data[1] = 1, outcome[1]
    else:
        data[0] = 0
        value = outcome[1] // E10 if word else to_bits(float(outcome[1]) / 1e14)
        data[8:16] = struct.pack("<Q", value)
    return bytes(data)


def default_tokens():
    # (sz at +0x48, wei at +0x49)
    return ((2, 8), (2, 8), (3, 6), (5, 18), (0, 8), (1, 5))


def spec_info(case):
    """Return (panic name or None, words by offset, log). Word values for an absent lane are left out."""
    rec, div = lookup(case), Div(case.faults)
    if rec is None:
        return None, {0: 2}, div.log
    tok, tokens = case.tok, case.tokens or default_tokens()
    count = case.n_tokens if case.n_tokens is not None else len(tokens)

    def wei(index):
        return tokens[index][1]

    def lane(word):
        product = word[0] * word[1]
        if high(product) > E14 - 1:
            return None
        q = low(div(product, E14))
        if word[0] == 0 and q:
            return None
        if tok >= count:
            raise Stop("unwrap")
        return float(q) / float(10 ** wei(tok))

    try:
        borrowed = lane((rec["a"], rec["ia"]))
        supplied = lane((rec["b"], rec["ib"]))
        if tok == 0:
            price = 1.0
        else:
            if tok >= count:
                raise Stop("unwrap")
            price = None
            for spot in case.lists.get(tok, ()):
                if spot >= len(case.spots):
                    raise Stop("index")
                base, used = case.spots[spot]
                if used == 0:
                    if base >= count:
                        raise Stop("unwrap")
                    shift = tokens[0][1] - tokens[base][0]
                    if shift < 0:
                        raise Stop("overflow")
                    price = float(rec["px"]) / float(10 ** shift)
                    break
        rate = float(rate_word(rec, div)) / 1e14
        ratio = inline_ratio(rec, div)
        if ratio is None:
            return None, {0: 2}, div.log
        if tok >= count:
            raise Stop("unwrap")
    except Stop as stop:
        return str(stop), None, div.log
    used = float(ratio) / 1e14
    keep = 1.0 - float(case.f) / 1e14
    words = {0: 1, 8: to_bits(used), 0x10: 0 if price is None else 1, 0x40: to_bits(rate), 0x48: to_bits(keep * (rate * used)),
             0x20: 0 if supplied is None else 1, 0x30: 0 if borrowed is None else 1,
             0x50: to_bits(float(rec["bal"]) / float(10 ** wei(tok))),
             0x58: to_bits(float(rec["ltv"] if rec["ltv"] is not None else 0) / 1e14)}
    if price is not None:
        words[0x18] = to_bits(price)
    if supplied is not None:
        words[0x28] = to_bits(supplied)
    if borrowed is not None:
        words[0x38] = to_bits(borrowed)
    return None, words, div.log


class Stop(Exception):
    pass


def rate_word(rec, div):
    return curve(rec, ratio_or_zero(rec, div), div)


def inline_ratio(rec, div):
    a, ia, b, ib = rec["a"], rec["ia"], rec["b"], rec["ib"]
    total = ceil_total(a, ia, div)
    product = b * ib
    if high(product) > E14 - 1:
        return None
    supplied = div(product, E14)
    if high(total) or (a == 0 and low(total)) or (b == 0 and low(supplied)):
        return None
    if low(supplied) == 0:
        return 0
    q = div(low(total) * E14, supplied)
    return None if high(q) else min(low(q), E14)


def lookup(case):
    for key, rec in tree_items(case):
        if key == case.tok:
            return rec
    return None


def tree_items(case):
    if case.shape == "miss":
        return [(case.tok - 1 & TOP, case.rec), (case.tok + 1, case.rec)]
    if case.shape == "below":
        return [(case.tok - 1 & TOP, case.rec)]
    if case.shape == "empty":
        return []
    return [(case.tok, case.rec)]


def clear_absent(words, data):
    data = bytearray(data)
    if words is None or words.get(0) == 2:
        return bytes(data[:8])
    for flag, value in ((0x10, 0x18), (0x20, 0x28), (0x30, 0x38)):
        if words[flag] == 0:
            data[value:value + 8] = bytes(8)
    return bytes(data)


def spec_run(case, before):
    base = before[OUT - HEAP_BASE:OUT - HEAP_BASE + OUT_SIZE]
    div = Div(case.faults)
    if case.kind == RATE:
        return ("xmm", to_bits(float(rate_word(case.rec, div)) / 1e14), div.log, ())
    if case.kind == RATE_INT:
        return ("rax", rate_word(case.rec, div) // E10, div.log, ())
    if case.kind in (UTIL_WORD, UTIL_F64):
        return ("out", result_bytes(base, util_result(case.rec, div), case.kind == UTIL_WORD), div.log, ())
    panic, words, log = spec_info(case)
    if panic:
        return ("panic", panic, log, ())
    data = bytearray(OUT_SIZE)
    for at, value in words.items():
        data[at:at + 8] = struct.pack("<Q", value)
    return ("info", bytes(data[:8] if words[0] == 2 else data), log, ())


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset((TOTALS, RATE))
        statics = machine.memory.statics
        for slot, hook in {SLOT_DIV: self.on_div, SLOT_UNWRAP: self.on_unwrap, SLOT_INDEX: self.on_index, SLOT_OVERFLOW: self.on_overflow}.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        statics[SLOT_RATE] = RATE
        self.case = None
        self.log = []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_div(self, machine):
        regs = machine.regs
        num, den = regs[RDI] | regs[RSI] << 64, regs[RDX] | regs[RCX] << 64
        index = len(self.log)
        self.log.append((num, den))
        if index in self.case.faults:
            q = self.case.faults[index]
        else:
            self.expect(den != 0, "divide by zero")
            q = num // den
        regs[RAX], regs[RDX] = low(q), high(q)
        machine.keep_rdx = True

    def on_unwrap(self, machine):
        raise Panicked("unwrap")

    def on_index(self, machine):
        raise Panicked("index")

    def on_overflow(self, machine):
        raise Panicked("overflow")

    def put_rec(self, at, rec):
        memory = self.machine.memory
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF for index in range(REC_SIZE)))
        tag = 2 if rec["ltv"] is None else 1
        for offset, value in ((0, tag), (8, rec["ltv"] or 0), (0x10, rec["px"]), (0x18, rec["bal"]), (0x40, rec["a"]), (0x58, rec["ia"]), (0x60, rec["b"]), (0x78, rec["ib"]),
                              (0x80, rec["mn"]), (0x88, rec["mx"]), (0x90, rec["kr"]), (0x98, rec["k"])):
            memory.write(at + offset, 8, value)

    def node(self, at, items, children=(), stale=None):
        memory = self.machine.memory
        memory.write(at + VAL_LEN, 2, len(items))
        for slot in range(11):
            value = stale if stale is not None and slot >= len(items) else 0x5A5A0000 + slot
            memory.write(at + KEY_AT + 8 * slot, 8, value)
        for slot, (key, rec) in enumerate(items):
            memory.write(at + KEY_AT + 8 * slot, 8, key)
            self.put_rec(at + REC_SIZE * slot, rec)
        for slot, child in enumerate(children):
            memory.write(at + EDGE_AT + 8 * slot, 8, child)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000)))
        memory.put_bytes(OUT, bytes((0x60 + index) & 0xFF for index in range(OUT_SIZE)))
        self.case, self.log = case, []
        if case.rec is not None and case.kind != INFO:
            self.put_rec(REC, case.rec)
        if case.kind == INFO:
            self.info_state(case)
        return bytes(memory.heap[:USED])

    def info_state(self, case):
        memory = self.machine.memory
        tokens = case.tokens or default_tokens()
        count = case.n_tokens if case.n_tokens is not None else len(tokens)
        memory.write(OWNER + 0xC8, 8, case.f)
        memory.write(META + 0x168, 8, SPOTS)
        memory.write(META + 0x170, 8, len(case.spots))
        memory.write(META + 0x180, 8, TOKENS)
        memory.write(META + 0x188, 8, count)
        for index, (sz, wei) in enumerate(tokens):
            at = TOKENS + index * TOKEN_STRIDE
            memory.write(at + 0x48, 1, sz)
            memory.write(at + 0x49, 1, wei)
            memory.write(at + 0x60, 8, 0)
        for index, (base, used) in enumerate(case.spots):
            memory.write(SPOTS + index * SPOT_STRIDE, 8, base)
            memory.write(SPOTS + index * SPOT_STRIDE + 8, 8, used)
        at = LISTS
        for tok, row in case.lists.items():
            memory.write(TOKENS + tok * TOKEN_STRIDE + 0x58, 8, at)
            memory.write(TOKENS + tok * TOKEN_STRIDE + 0x60, 8, len(row))
            for spot in row:
                memory.write(at, 8, spot)
                at += 8
        items = tree_items(case)
        rec = case.rec
        decoy = dict(rec, ia=rec["ia"] ^ 0x55, kr=rec["kr"] ^ 0x77) if rec else None
        tok = case.tok
        if case.shape == "empty":
            memory.write(OWNER + 0xD0, 8, 0)
            memory.write(OWNER + 0xD8, 8, 0)
            return
        if case.shape == "deep":
            left, right, root = NODES + NODE_STRIDE, NODES + 2 * NODE_STRIDE, NODES
            self.node(left, [(tok - 2 & TOP, decoy), (tok - 1 & TOP, decoy)], stale=tok)
            self.node(right, [(tok, rec), (tok + 2, decoy)], stale=tok + 1)
            # The root key sits below the target, so the walk must take the second edge.
            self.node(root, [(tok - 1 & TOP, decoy)], (left, right))
            memory.write(OWNER + 0xD0, 8, root)
            memory.write(OWNER + 0xD8, 8, 1)
            return
        rows = list(items)
        if case.shape in ("miss", "below"):
            rows = sorted(rows, key=lambda row: row[0])
            self.node(NODES, [(key, decoy) for key, _ in rows], stale=tok)
        else:
            lows = [(tok - 3 + index & TOP, decoy) for index in range(3)] if tok >= 3 else []
            self.node(NODES, lows + rows + [(tok + 1, decoy)], stale=tok)
        memory.write(OWNER + 0xD0, 8, NODES)
        memory.write(OWNER + 0xD8, 8, 0)

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        args = {RATE: {RDI: REC}, RATE_INT: {RDI: REC}, UTIL_WORD: {RDI: OUT, RSI: REC}, UTIL_F64: {RDI: OUT, RSI: REC},
                INFO: {RDI: OUT, RSI: case.tok, RDX: OWNER, RCX: META}}[case.kind]
        try:
            value = machine.run(case.kind, args)
        except Panicked as panic:
            return before, ("panic", str(panic), self.log, ())
        after = bytes(machine.memory.heap[:USED])
        start, end = OUT - HEAP_BASE, OUT - HEAP_BASE + OUT_SIZE
        if case.kind == INFO:
            words = {0: struct.unpack_from("<Q", after, start)[0]}
            for at in (0x10, 0x20, 0x30):
                words[at] = struct.unpack_from("<Q", after, start + at)[0]
            if after[:start] + after[end:] != before[:start] + before[end:]:
                raise Halt("state changed outside the result")
            head = after[start:end]
            head = head[:8] if words[0] == 2 else clear_absent(words, head)
            return before, ("info", head, self.log, ())
        if after[:start] + after[end:] != before[:start] + before[end:]:
            raise Halt("state changed outside the result")
        if case.kind == RATE:
            return before, ("xmm", machine.xmm[0] & MASK[8], self.log, ())
        if case.kind == RATE_INT:
            return before, ("rax", value, self.log, ())
        if value != OUT:
            raise Halt("result pointer")
        return before, ("out", after[start:end], self.log, ())


def base_records():
    good = dict(mn=0, mx=E14, kr=5 * 10 ** 12, k=8 * 10 ** 13)
    rows = [
        ("empty market", record()),
        ("half used", record(a=50, b=100)),
        ("at the bend", record(a=80, b=100)),
        ("one unit above the bend", record(a=800000000000001, b=1000000000000000)),
        ("one unit below the bend", record(a=799999999999999, b=1000000000000000)),
        ("fully used", record(a=100, b=100)),
        ("borrow above supply", record(a=300, b=100)),
        ("min floor", record(a=1, b=10 ** 14, mn=2 * 10 ** 11)),
        ("rounding low arm", record(a=7, b=9, mn=123456789, kr=987654321012, k=33333333333333)),
        ("rounding high arm", record(a=8, b=9, kr=987654321012, mx=7777777777777, k=33333333333333)),
        ("bend below floor", record(a=1, b=10, mn=9 * 10 ** 12, kr=10 ** 12, k=5 * 10 ** 13)),
        ("bend equal to floor", record(a=1, b=10, mn=10 ** 12, kr=10 ** 12, k=5 * 10 ** 13)),
        ("top below bend", record(a=9, b=10, kr=9 * 10 ** 12, mx=10 ** 12, k=5 * 10 ** 13)),
        ("top equal to bend", record(a=9, b=10, kr=9 * 10 ** 12, mx=9 * 10 ** 12, k=5 * 10 ** 13)),
        ("kink zero, some use", record(a=1, b=4, kr=10 ** 12, mx=10 ** 13, k=0)),
        ("kink zero, no use", record(kr=10 ** 12, mx=10 ** 13, k=0)),
        ("kink at one", record(a=1, b=4, kr=10 ** 12, mx=10 ** 13, k=E14)),
        ("kink at one, fully used", record(a=5, b=4, kr=10 ** 12, mx=10 ** 13, k=E14)),
        ("kink past one", record(a=9, b=4, kr=10 ** 12, mx=10 ** 13, k=E14 + 5)),
        ("kink just below one", record(a=9, b=4, kr=10 ** 12, mx=10 ** 13, k=E14 - 1)),
        ("ceil adds one", record(a=3, ia=E14 + 1, b=1000000, ib=E14)),
        ("exact product no ceil", record(a=3, ia=2 * E14, b=1000000, ib=E14)),
        ("borrow index below one", record(a=3, ia=1, b=1, ib=E14)),
        ("supply floors to zero", record(a=3, b=1, ib=1)),
        ("no supply with debt", record(a=3, b=0)),
        ("no shares, index zero", record(a=0, ia=0, b=0, ib=0)),
        ("borrow product at the top word", record(a=TOP, ia=E14, b=TOP, ib=E14)),
        ("ceil crosses 2^64", record(a=1 << 63, ia=2 * E14 + 1, b=1 << 50, ib=E14)),
        ("ceil ends at 2^64", record(a=1 << 63, ia=2 * E14, b=1 << 50, ib=E14)),
        ("ceil ends at 2^64 minus one", record(a=TOP, ia=E14, b=1 << 50, ib=E14)),
        ("borrow overflow with supply overflow", record(a=TOP, ia=TOP, b=TOP, ib=TOP)),
        ("supply just fits", record(a=5, b=TOP, ib=E14)),
        ("supply one past the word", record(a=5, b=1 << 63, ib=2 * E14)),
        ("supply just past the word", record(a=5, b=1 << 63, ib=2 * E14 + 1)),
        ("quotient at 2^64", record(a=1 << 50, b=1, ib=610351562500, ia=E14)),
        ("ratio above the cap by far", record(a=10 ** 18, b=6 * 10 ** 12, ia=E14, ib=1)),
        ("ratio past 2^64", record(a=10 ** 19, b=1, ia=E14, ib=E14)),
        ("ratio just under 2^64", record(a=184467, b=1)),
        ("ratio at the cut", record(a=184468, b=1)),
        ("big rates", record(a=7, b=9, mn=TOP - 100, kr=TOP - 10, mx=TOP, k=5 * 10 ** 13)),
        ("big rates high", record(a=8, b=9, mn=0, kr=TOP - 100, mx=TOP, k=5 * 10 ** 13)),
        ("wide span", record(a=9, b=10, kr=0, mx=TOP, k=0)),
        ("wide span low", record(a=1, b=10, mn=0, kr=TOP, k=99 * 10 ** 12)),
        ("wide span floor one", record(a=1, b=10, mn=1, kr=TOP, k=5 * 10 ** 13)),
    ]
    faults = [
        ("no borrow shares with a quotient", record(a=0, b=10), {0: 5}),
        ("no supply shares with a quotient", record(a=4, b=0), {1: 5}),
        ("supply quotient with a high word", record(a=4, b=10), {1: (1 << 64) | 40}),
        ("both quotients zero", record(a=4, b=10), {0: 0, 1: 0}),
        ("low arm quotient high word", record(a=1, b=10), {3: 1 << 64}),
        ("low arm wide quotient", record(a=1, b=10, mn=0, kr=TOP, k=5 * 10 ** 13), {3: E14 * 3}),
        ("low arm guard edge", record(a=1, b=10, mn=0, kr=1 << 63, k=5 * 10 ** 13), {3: (E14 << 1) - 1}),
        ("low arm guard hit", record(a=1, b=10, mn=0, kr=1 << 63, k=5 * 10 ** 13), {3: E14 << 1}),
        ("low arm add wraps", record(a=1, b=10, mn=TOP - 2, kr=TOP, k=5 * 10 ** 13), {4: 3}),
        ("low arm add just fits", record(a=1, b=10, mn=TOP - 2, kr=TOP, k=5 * 10 ** 13), {4: 2}),
        ("high arm quotient high word", record(a=9, b=10), {3: 1 << 64}),
        ("high arm wide quotient", record(a=9, b=10, kr=0, mx=TOP, k=5 * 10 ** 13), {3: E14 * 3}),
        ("high arm guard edge", record(a=9, b=10, kr=0, mx=1 << 63, k=5 * 10 ** 13), {3: (E14 << 1) - 1}),
        ("high arm guard hit", record(a=9, b=10, kr=0, mx=1 << 63, k=5 * 10 ** 13), {3: E14 << 1}),
        ("high arm add wraps", record(a=9, b=10, kr=TOP - 2, mx=TOP, k=5 * 10 ** 13), {4: 3}),
        ("high arm add just fits", record(a=9, b=10, kr=TOP - 2, mx=TOP, k=5 * 10 ** 13), {4: 2}),
        ("high arm kink forced above u", record(a=9, b=10, k=10 ** 15), {2: E14 * 2}),
        ("low arm product at the guard", record(a=1, b=10, mn=0, kr=EDGE_RIGHT, k=5 * 10 ** 13), {3: EDGE_LEFT}),
        ("high arm product at the guard", record(a=9, b=10, kr=0, mx=EDGE_RIGHT, k=5 * 10 ** 13), {3: EDGE_LEFT}),
    ]
    return [(name, rec, {}) for name, rec in rows] + faults


def info_cases():
    spots = ((1, 1), (2, 0), (3, 0), (4, 0), (5, 1), (9, 0))
    lists = {1: (0, 1), 2: (2,), 3: (0, 4), 4: (5,), 5: (6,)}
    tokens = default_tokens()
    base = record(a=800, ia=E14 + 3, b=1000, ib=E14 + 9, ltv=5 * 10 ** 13, px=123456789, bal=987654321)
    rows = [
        ("usd token", dict(tok=0, rec=base, f=10 ** 13)),
        ("spot priced token", dict(tok=1, rec=base, f=10 ** 13)),
        ("deep tree", dict(tok=1, rec=base, f=10 ** 13, shape="deep")),
        ("deep tree second token", dict(tok=2, rec=base, f=3 * 10 ** 13, shape="deep")),
        ("high token shift", dict(tok=2, rec=base, f=0)),
        ("no live spot", dict(tok=3, rec=base, f=0)),
        ("tree miss", dict(tok=1, rec=base, shape="miss")),
        ("empty tree", dict(tok=1, rec=base, shape="empty")),
        ("no ltv", dict(tok=1, rec=dict(base, ltv=None), f=10 ** 13)),
        ("ltv tag other", dict(tok=1, rec=dict(base, ltv=None), f=E14)),
        ("reserve above one", dict(tok=1, rec=base, f=2 * E14)),
        ("reserve top word", dict(tok=1, rec=base, f=TOP)),
        ("kink above bend", dict(tok=1, rec=record(a=9, b=10, ltv=1, px=1 << 63, bal=TOP), f=1)),
        ("large share words", dict(tok=1, rec=record(a=1 << 40, b=1 << 41, ia=1 << 60, ib=1 << 60, px=TOP, bal=1), f=5)),
        ("zero use", dict(tok=1, rec=record(a=0, b=5), f=7)),
        ("no supply with debt", dict(tok=1, rec=record(a=5, b=0), f=7)),
        ("supply floors to zero", dict(tok=1, rec=record(a=5, b=1, ib=1), f=7)),
        ("borrow total overflows", dict(tok=1, rec=record(a=TOP, ia=TOP, b=5), f=7)),
        ("borrow ceil past word", dict(tok=1, rec=record(a=1 << 63, ia=2 * E14 + 1, b=1 << 50), f=7)),
        ("borrow ends at 2^64", dict(tok=1, rec=record(a=1 << 63, ia=2 * E14, b=1 << 50), f=7)),
        ("borrow product fits, top", dict(tok=1, rec=record(a=TOP, ia=E14, b=1 << 50), f=7)),
        ("supply total overflows", dict(tok=1, rec=record(a=5, b=TOP, ib=TOP), f=7)),
        ("supply one past", dict(tok=1, rec=record(a=5, b=1 << 63, ib=2 * E14), f=7)),
        ("supply just past", dict(tok=1, rec=record(a=5, b=1 << 63, ib=2 * E14 + 1), f=7)),
        ("supply just fits", dict(tok=1, rec=record(a=5, b=TOP, ib=E14), f=7)),
        ("ratio past 2^64", dict(tok=1, rec=record(a=10 ** 19, b=1), f=7)),
        ("ratio at 184467", dict(tok=1, rec=record(a=184467, b=1), f=7)),
        ("ratio at the cut", dict(tok=1, rec=record(a=184468, b=1), f=7)),
        ("ratio capped", dict(tok=1, rec=record(a=3, b=1), f=7)),
        ("token past table, usd lookalike", dict(tok=6, rec=base, f=0, lists={})),
        ("spot row past list", dict(tok=5, rec=base, f=0)),
        ("spot base past table", dict(tok=4, rec=base, f=0)),
        ("price shift underflows", dict(tok=2, rec=base, f=0, tokens=((2, 2), (2, 8), (3, 6), (5, 18), (0, 8), (1, 5)))),
        ("price shift zero", dict(tok=2, rec=base, f=0, tokens=((2, 5), (2, 8), (3, 6), (5, 18), (0, 8), (1, 5)))),
        ("sizes differ per token", dict(tok=3, rec=base, f=0, lists={3: (1,)})),
        ("bad borrow fault", dict(tok=1, rec=record(a=0, b=5), f=7, faults={0: 9})),
        ("bad supply fault", dict(tok=1, rec=record(a=5, b=0), f=7, faults={1: 9})),
        ("inline bad borrow fault", dict(tok=1, rec=record(a=0, b=5), f=7, faults={4: 9})),
        ("inline bad supply fault", dict(tok=1, rec=record(a=5, b=0), f=7, faults={5: 9})),
        ("inline supply zero", dict(tok=1, rec=record(a=5, b=5), f=7, faults={5: 0})),
        ("inline supply high word", dict(tok=1, rec=record(a=5, b=5), f=7, faults={5: 1 << 64})),
        ("inline quotient high word", dict(tok=1, rec=record(a=5, b=5), f=7, faults={6: 1 << 64})),
        ("inline borrow high word", dict(tok=1, rec=record(a=5, b=5), f=7, faults={4: 1 << 64})),
        ("one borrow share", dict(tok=1, rec=record(a=1, b=5), f=7)),
        ("one supply share", dict(tok=1, rec=record(a=1, b=1), f=7)),
        ("miss past the last key", dict(tok=1, rec=base, shape="below")),
        ("supply product at the guard", dict(tok=1, rec=record(a=5, b=EDGE_LEFT, ib=EDGE_RIGHT), f=7)),
        ("borrow product at the guard", dict(tok=1, rec=record(a=EDGE_LEFT, ia=EDGE_RIGHT, b=1 << 40), f=7)),
        ("second lane bound", dict(tok=0, rec=record(a=0, b=5), f=7, n_tokens=0, faults={0: 9})),
        ("last bound", dict(tok=0, rec=record(a=0, b=0), f=7, n_tokens=0, faults={0: 9, 1: 9})),
    ]
    out = []
    for name, fields in rows:
        data = dict(spots=spots, lists=lists)
        data.update(fields)
        out.append(Case("info " + name, INFO, **data))
    return out


def named_cases():
    rows = []
    for kind in (RATE, RATE_INT, UTIL_WORD, UTIL_F64):
        for name, rec, faults in base_records():
            rows.append(Case(name, kind, rec=rec, faults=faults))
    return rows + info_cases()


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


def draw(stream):
    word = next(stream)
    kind = word & 7
    value = next(stream)
    if kind == 0:
        return value
    if kind == 1:
        return value >> (word >> 8 & 63)
    if kind == 2:
        return value % (2 * E14)
    if kind == 3:
        return E14 + (value % 2001) - 1000
    if kind == 4:
        return value % 1000
    if kind == 5:
        return (1 << (word >> 8 & 63)) + (value % 5) - 2 & TOP
    return value % (10 ** 18)


def vector_cases(count):
    stream = lcg(0x1234ABCD)
    rows = []
    for index in range(count):
        rec = record(a=draw(stream), ia=draw(stream), b=draw(stream), ib=draw(stream), mn=draw(stream), mx=draw(stream), kr=draw(stream), k=draw(stream))
        kind = (RATE, RATE_INT, UTIL_WORD, UTIL_F64)[index % 4]
        rows.append(Case("v%d" % index, kind, rec=rec))
        if index % 4 == 0:
            rec = dict(rec, ltv=draw(stream) if next(stream) & 1 else None, px=draw(stream), bal=draw(stream))
            rows.append(Case("i%d" % index, INFO, rec=rec, tok=1, f=draw(stream), spots=((1, 1), (2, 0)), lists={1: (0, 1)}))
    return rows


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before)
        if got != want:
            raise EvidenceError("case disagrees with the rule list: %s %r %r" % (case.name, got, want))
        outcomes.append(got)
    return outcomes


def run_value(harness, kind, rec):
    case = Case("probe", kind, rec=rec)
    return harness.run(case)[1]


def reciprocal_rows():
    rows = []
    for name, multiplier, shift, limit in (("rate_e10", MUL_RATE, SHIFT_RATE, 1 << 64), ("utilization_e10", MUL_UTIL, SHIFT_UTIL, E14 + 1)):
        spare = multiplier * E10 - (1 << shift)
        worst = (limit - 1) * spare
        if spare <= 0 or worst >= 1 << shift:
            raise EvidenceError("reciprocal bound fails for " + name)
        rows.append((name, "%#x" % multiplier, shift, spare, limit, worst, 1 << shift))
    return rows


def shadow_rows():
    """Largest quotient and product each arm can see, from the argument word limits alone."""
    rows = []
    low_arm = (E14 - 1) * E14 // E14
    high_arm = E14
    rows.append(("low arm f", "u < k, so u*1e14/k < 1e14", low_arm, "below 2^64"))
    rows.append(("high arm f", "k < u <= 1e14 and (u-k)*1e14/(1e14-k) <= 1e14", high_arm, "below 2^64"))
    if high_arm * TOP >= GUARD:
        raise EvidenceError("product guard is reachable")
    rows.append(("product", "f * (2^64-1) with f <= 1e14", high_arm * TOP, "below 1e14*2^64"))
    rows.append(("sum", "base + floor(f*(end-base)/1e14) with f <= 1e14", "end", "below 2^64"))
    rows.append(("kink bound", "the high arm needs k < u <= 1e14", E14 - 1, "k never above 1e14-1 there"))
    return rows


def fault_only_rows(image, table):
    """Rows that no run reaches unless the divide stub answers a false quotient."""
    harness = Harness(image)
    for case in named_cases() + vector_cases(800):
        if not case.faults:
            harness.run(case)
    plain = harness.machine.seen
    rows = []
    for target in TARGETS:
        chosen = [row.va for row in table[target] if row.va not in plain and row.op not in ("int3", "nop")]
        rows.append((NAMES[target], len(chosen), " ".join("%#x" % va for va in chosen)))
    return rows


def curve_rows(harness):
    configs = ((0, E14, 5 * 10 ** 12, 8 * 10 ** 13), (2 * 10 ** 12, 5 * 10 ** 13, 10 ** 13, 9 * 10 ** 13))
    rows = []
    for mn, mx, kr, k in configs:
        for percent in (0, 25, 50, 75, 80, 90, 100, 150):
            rec = record(a=percent, b=100, mn=mn, mx=mx, kr=kr, k=k)
            word = run_value(harness, RATE_INT, rec)[1]
            value = run_value(harness, RATE, rec)[1]
            rows.append((mn, mx, kr, k, percent, word, repr(to_float(value))))
    return rows


def ratio_rows(harness):
    rows = []
    for name, a, b, ia, ib in (("half", 50, 100, E14, E14), ("full", 100, 100, E14, E14), ("over", 300, 100, E14, E14), ("no supply", 3, 0, E14, E14),
                               ("just under the cut", 184467, 1, E14, E14), ("at the cut", 184468, 1, E14, E14), ("supply past the word", 5, 1 << 63, E14, 2 * E14), ("borrow past the word", TOP, 1, TOP, E14)):
        rec = record(a=a, b=b, ia=ia, ib=ib, mn=1000 * E10, kr=2000 * E10, mx=5000 * E10, k=5 * 10 ** 13)
        rate = run_value(harness, RATE_INT, rec)[1]
        out = run_value(harness, UTIL_WORD, rec)[1]
        result = "err %d" % out[1] if out[0] else "ok %d" % struct.unpack_from("<Q", out, 8)[0]
        info = harness.run(Case("probe", INFO, rec=rec, tok=0, spots=(), lists={}))[1][1]
        row = struct.unpack_from("<Q", info)[0]
        rows.append((name, a, b, rate, result, "absent" if row == 2 else repr(to_float(struct.unpack_from("<Q", info, 8)[0]))))
    return rows


def constant_rows(image):
    rows = []
    for name, va, want in (("1e14", F_E14, 1e14), ("1.0", F_ONE, 1.0)):
        bits = struct.unpack_from("<Q", image.blob, image.offset(va))[0]
        if to_float(bits) != want:
            raise EvidenceError("constant changed: " + name)
        rows.append((name, "%#x" % va, repr(want), "%#x" % bits))
    return rows


def table_rows(image):
    rows = []
    for name, va, count in (("token power table", TABLE_TOKEN, 19), ("price power table", TABLE_PRICE, 12)):
        for index in range(count):
            bits = struct.unpack_from("<Q", image.blob, image.offset(va + 8 * index))[0]
            if to_float(bits) != float(10 ** index):
                raise EvidenceError("power table entry %s %d" % (name, index))
            rows.append((name, "%#x" % va, index, "%#x" % bits))
    return rows


def site_rows(image):
    rows = []
    text_va, text = image.text_bytes()
    relative = image.relative()
    for name, slot, target in (("rate_f64", SLOT_RATE, RATE), ("utilization_f64", SLOT_UTIL_F64, UTIL_F64), ("token_info_row", SLOT_INFO, INFO)):
        if relative.get(slot) != target:
            raise EvidenceError("slot does not hold the target: %#x" % slot)
        sites = []
        at = 0
        while True:
            at = text.find(b"\xff\x15", at)
            if at < 0:
                break
            if text_va + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
                sites.append(text_va + at)
            at += 1
        rows.append((name, "%#x" % slot, "%#x" % target, "slot", " ".join("%#x" % site for site in sites)))
    for name, target in (("rate_e10", RATE_INT), ("utilization_e10", UTIL_WORD), ("token_totals", TOTALS)):
        sites = []
        at = 0
        while True:
            at = text.find(b"\xe8", at)
            if at < 0 or at + 5 > len(text):
                break
            if text_va + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
                sites.append(text_va + at)
            at += 1
        rows.append((name, "-", "%#x" % target, "direct", " ".join("%#x" % site for site in sites)))
    return rows


def key_at(image, va, size):
    return bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")


def name_rows(image):
    start, end = image.exact_fde(SERDE_FN)
    data = bytes(image.blob[image.offset(start):image.offset(end)])
    rows = []
    fields = []
    for match in re.finditer(rb"\x48[\xb8\xb9](.{8})", data, re.S):
        fields.append(struct.unpack("<Q", match[1])[0])
    if MIN_WORD not in fields or 0x7461725F6B6E696B not in fields or struct.pack("<Q", (MIN_WORD + MAX_STEP) & TOP) != b"max_rate":
        raise EvidenceError("rate key words moved")
    rows.append(("min_rate", "movabs", struct.pack("<Q", MIN_WORD).decode()))
    rows.append(("max_rate", "movabs + 0x9f800", struct.pack("<Q", (MIN_WORD + MAX_STEP) & TOP).decode()))
    rows.append(("kink_rate", "movabs + byte", struct.pack("<Q", 0x7461725F6B6E696B).decode() + "e"))
    rows.append(("kink_utilization", "%#x" % KEY_ADDR, key_at(image, KEY_AT_TEXT, 16)))
    start, end = image.exact_fde(INFO_SERIALIZER)
    data = bytes(image.blob[image.offset(start):image.offset(end)])
    wanted = []
    for match in re.finditer(rb"\x48\x8d\x35(.{4})", data, re.S):
        at = match.start()
        window = data[at + 7:at + 18]
        length = window.find(b"\xba")
        if length < 0:
            continue
        size = struct.unpack_from("<I", window, length + 1)[0]
        target = start + at + 7 + struct.unpack("<i", match[1])[0]
        if 2 < size <= 16:
            wanted.append(key_at(image, target, size))
    for key in ("borrowYearlyRate", "supplyYearlyRate", "balance", "utilization", "oraclePx", "ltv", "totalSupplied", "totalBorrowed"):
        if key not in wanted:
            raise EvidenceError("key missing from the info serializer: " + key)
        rows.append((key, "%#x" % INFO_SERIALIZER, key))
    return rows


KEY_AT_TEXT = KEY_ADDR


def writer_rows(image):
    """The 32 byte copy into record +0x80 in the token config writer: flag byte set, four words, in key order."""
    size = len(WRITE_BYTES) // 2
    data = bytes(image.blob[image.offset(WRITE_SITE):image.offset(WRITE_SITE) + size])
    if data.hex() != WRITE_BYTES:
        raise EvidenceError("writer bytes moved")
    return [("%#x" % WRITE_SITE, data.hex(), "lea (rbx+r14),rax; add -0x30,rax; 32 bytes from input +8 to the tree value at +0x80")]


def edits_for(image, rows, seen):
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(i for i in range(row.size) if data[i] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] in (None, RSP) or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def first_failure(harness, cases):
    for case in cases:
        try:
            before, got = harness.run(case)
            if got != spec_run(case, before):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


EXPECTED_SURVIVORS = {
    (0x2A3305A, "immediate"): "the high word for an inline divide when the total has a high word: that total has already left through 0x2a33045, so the value is never read",
}


def cases_for(target, cases):
    wanted = {TOTALS: INFO}.get(target, target)
    return [case for case in cases if case.kind == wanted]


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    extra = vector_cases(240)
    for target in TARGETS:
        chosen = cases_for(target, cases)
        plain = [case for case in chosen + cases_for(target, extra) if not case.faults]
        forced = [case for case in chosen if case.faults]
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            if first_failure(harness, plain) is not None:
                results.append((va, kind, "killed", "plain input"))
            elif first_failure(harness, forced) is not None:
                results.append((va, kind, "killed", "injected quotient only"))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=600):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    fault_only = fault_only_rows(image, table)
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, sites=site_rows(image), constants=constant_rows(image), tables=table_rows(image), names=name_rows(image),
                  reciprocals=reciprocal_rows(), shadows=shadow_rows(), curve=curve_rows(harness), ratios=ratio_rows(harness), fault_only=fault_only, writer=writer_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    kind, value, log, events = outcome
    if isinstance(value, bytes):
        text = value.hex()
    else:
        text = str(value)
    return kind, hashlib.sha256(text.encode()).hexdigest()[:16], len(log), ",".join(events)


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("call-sites.tsv", ("function", "slot", "target", "form", "sites"), result["sites"])
    tsv("constants.tsv", ("name", "address", "value", "bits"), result["constants"])
    tsv("power-tables.tsv", ("table", "address", "index", "bits"), result["tables"])
    tsv("field-names.tsv", ("name", "source", "text"), result["names"])
    tsv("reciprocals.tsv", ("divide", "multiplier", "shift", "spare", "inputs_below", "worst_error", "two_to_shift"), result["reciprocals"])
    tsv("shadowed-guards.tsv", ("value", "why", "largest", "bound"), result["shadows"])
    tsv("curve-samples.tsv", ("min_rate", "max_rate", "kink_rate", "kink_utilization", "borrowed_per_100_supplied", "rate_e10", "rate_f64"), result["curve"])
    tsv("ratio-edges.tsv", ("case", "borrowed", "supplied", "rate_e10", "utilization_e10", "info_utilization"), result["ratios"])
    tsv("fault-only-rows.tsv", ("function", "rows", "addresses"), result["fault_only"])
    tsv("writer-site.tsv", ("site", "bytes", "reading"), result["writer"])
    tsv("outcomes.tsv", ("entry", "case", "form", "result_digest", "divides", "events"),
        [("%#x" % case.kind, case.name) + describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived"),
                                "injected_only": sum(1 for r in rows if r[3] == "injected quotient only")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
