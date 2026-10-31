#!/usr/bin/env python3
"""Pin node #94 HyperEVM read precompile 0x812: gates, gas, and the eight output words.

0x324bdf0 answers the call for one token: a set check, a length cap, a gas gate, the uint64 decode, the token
bound, the record lookup, two totals, the rate and utilization callees, then eight big endian words. The real
bytes run under recording stubs with real B-tree fixtures, a separately written rule list predicts the whole
heap of every run, and every reached conditional row, immediate and field offset is mutated. No objdump or
readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/reserve_read_precompile.py --out <dir>
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
            return finish("cvtsi2sd", ("x", reg), rm, width)
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
            value = self.get(row.b, row.width)
            self.set_low(row.a[1], to_bits(float(value - (1 << (8 * row.width)) if value & SIGN[row.width] else value)))
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


PRECOMPILE = 0x324BDF0
LOOKUP = 0x3790F20
TARGETS = (PRECOMPILE, LOOKUP)
NAMES = {PRECOMPILE: "reserve_read_0x812", LOOKUP: "reserve_lookup"}

DECODE = 0x37E6D50
FORMAT = 0x37F3190
DROP = 0x3C1ADA0
WRAP = 0x3C02770
RATE_INT = 0x37412A0
UTIL_WORD = 0x3741010
UTIL_F64 = 0x3741160
BYTES_FROM_VEC = 0x1511380

SLOT_DIV = 0x576E1A8
SLOT_MEMCMP = 0x576E488
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_BYTES = 0x576E240
SLOT_LOOKUP = 0x5775518
SLOT_UTIL_F64 = 0x5775520
SLOT_WRAP = 0x5775510
SLOT_UNWRAP = 0x576E470
SLOT_INDEX = 0x576DFC8
SLOT_OVERFLOW = 0x576E150
HOOK_SLOTS = (SLOT_DIV, SLOT_MEMCMP, SLOT_ALLOC, SLOT_FREE, SLOT_ALLOC_FAIL, SLOT_BYTES, SLOT_UNWRAP, SLOT_INDEX, SLOT_OVERFLOW)
TABLE_SLOTS = (0x56A6AF8, 0x56DFB20)
MARK_BASE = 0x7700000000
MARK_LOOKUP = MARK_BASE + 1
MARK_UTIL = MARK_BASE + 2
MARK_DROP_BYTES = MARK_BASE + 3

ADDRESS_CONST = 0x582610
ADDRESS = 0x812
F_RESERVE = 0x20AE90
F_ONE = 0x20A730
F_TWO64 = 0x20A510
F_TOP = 0x20A218
F_TWO63 = 0x20A7F0
LANE_A = 0x203E80
LANE_B = 0x202EA0
E0_DISPLAY = 0x59A8D0
INNER_DISPLAY_ARM = 0x3998418
INNER_TABLE = 0x5A56C4
PREFIX_E1 = 0x1EAE46
TAG_TOKEN = 0xEA
TAG_BOLE = 0xE1
INNER_MISSING = 0
INNER_INTERNAL = 0xA

E14 = 10 ** 14
E10 = 10 ** 10
TOP = MASK[8]
TOP128 = (1 << 128) - 1
GUARD = E14 << 64
MUL_E10 = 0xDBE6FECEBDEDD5BF
SHIFT_E10 = 97
LENGTH_CAP = 2000
GAS_BASE = 1000
GAS_PER_BYTE = 33
WORDS = 8
OUTPUT_SIZE = 0x100
DOC_BASE = 2000
DOC_PER_BYTE = 65

OUT = HEAP_BASE + 0x200
OUT_SIZE = 0x28
CTX = HEAP_BASE + 0x300
META = HEAP_BASE + 0x400
SET_ROOT = HEAP_BASE + 0x600
OWNER = HEAP_BASE + 0x680
MAP = OWNER + 0xC8
INPUT = HEAP_BASE + 0x780
INPUT_DATA = HEAP_BASE + 0x7A0
VTABLE = HEAP_BASE + 0x7C0
SET_NODES = HEAP_BASE + 0x900
SET_NODE_STRIDE = 0x100
ALLOC_ONE = HEAP_BASE + 0xC00
ALLOC_TWO = HEAP_BASE + 0xD00
NODES = HEAP_BASE + 0x1000
NODE_STRIDE = 0x900
USED = 0x4000
REC_SIZE = 0xB0
VAL_LEN = 0x7F2
KEY_AT = 0x798
EDGE_AT = 0x7F8
SET_KEY_AT = 8
SET_LEN = 0xE6
SET_EDGE_AT = 0xE8
DATA_WORD = 0x0123456789ABCDEF
FORMATTED = (0xE500000000000000, 0xE600000000000000, 0xE700000000000000)


class Case:
    __slots__ = ("name", "kind", "keys", "set_shape", "n", "gas", "ok", "tok", "count", "shape", "rec", "c", "r", "uw", "uf",
                 "out_len", "faults", "oom", "lookup_fail", "real", "direct_key")

    def __init__(self, name, kind=PRECOMPILE, keys=(), set_shape="absent", n=32, gas=10 ** 6, ok=True, tok=5, count=10, shape="leaf", rec=None, c=0,
                 r=1234, uw=(0, 4321), uf=(0, 0.25), out_len=OUTPUT_SIZE, faults=None, oom=None, lookup_fail=False, real=False, direct_key=None):
        self.name, self.kind, self.keys, self.set_shape, self.n, self.gas, self.ok = name, kind, keys, set_shape, n, gas, ok
        self.tok, self.count, self.shape, self.rec, self.c, self.r, self.uw, self.uf = tok, count, shape, rec or record(), c, r, uw, uf
        self.out_len, self.faults, self.oom, self.lookup_fail, self.real, self.direct_key = out_len, faults or {}, oom, lookup_fail, real, direct_key


def record(a=0, ia=E14, b=0, ib=E14, mn=0, mx=E14, kr=5 * 10 ** 12, k=8 * 10 ** 13, tag=2, ltv=0, px=0, bal=0):
    return dict(a=a, ia=ia, b=b, ib=ib, mn=mn, mx=mx, kr=kr, k=k, tag=tag, ltv=ltv, px=px, bal=bal)


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


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


def tail(value):
    """The bytes after the f64 product: NaN and both infinities give 0, the rest truncates and saturates."""
    if value != value or value in (math.inf, -math.inf) or value <= 0.0:
        return 0
    if value >= 18446744073709551616.0:
        return TOP
    return int(value)


def supply_rate(r, u, c):
    return tail((fdiv(float(c), -1e14) + 1.0) * (float(signed32(r)) * u))


def plain_supply(r, u, c):
    return (fdiv(float(c), -1e14) + 1.0) * (float(signed32(r)) * u)


def total_word(amount, index, div):
    """Floor of amount*index/1e14; zero when the amount is zero or the quotient has a high word."""
    product = amount * index
    q = div(product, E14)
    return 0 if amount == 0 or high(product) > E14 - 1 else low(q)


def rec_found(case):
    return case.shape in ("leaf", "deep")


def blocked(case):
    return ADDRESS in case.keys and case.set_shape != "absent"


def be_word(value):
    return b"\0" * 24 + struct.pack(">Q", value)


def output_bytes(words):
    return b"".join(be_word(value) for value in words)


def gas_in(n):
    return GAS_BASE + GAS_PER_BYTE * n


def total_gas(n, out_len):
    wide = out_len * GAS_PER_BYTE
    if wide > TOP:
        return TOP
    value = gas_in(n) + wide
    return TOP if value > TOP else value


def spec_run(case, before):
    state = bytearray(before)
    events = []

    def poke(addr, data):
        state[addr - HEAP_BASE:addr - HEAP_BASE + len(data)] = data

    def result(stamp):
        return ("run", bytes(state), div.log, tuple(events), stamp)

    def starved():
        poke(OUT, bytes(16) + struct.pack("<Q", 1 << 63))
        return result("starved")

    def refused(tag, payload):
        events.extend((("format", tag, payload), ("drop", tag)))
        poke(OUT, bytes(16) + struct.pack("<QQQ", *FORMATTED))
        return result("refused %#x %#x" % (tag, payload))

    div = Div(case.faults)
    if case.kind == LOOKUP:
        if rec_found(case):
            poke(OUT, b"\0")
            poke(OUT + 8, struct.pack("<Q", value_address(case)))
            return result("found")
        poke(OUT, bytes((1, 9)))
        return result("missing")
    if blocked(case) or case.n > LENGTH_CAP or gas_in(case.n) > case.gas:
        return starved()
    if not case.ok:
        events.append(("alloc", 13))
        if case.oom == 1:
            return ("panic", (1, 13), div.log, tuple(events), "panic")
        poke(ALLOC_ONE, b"Invalid input")
        poke(OUT, bytes(16) + struct.pack("<QQQ", 13, ALLOC_ONE, 13))
        return result("invalid input")
    if case.tok >= case.count:
        return refused(TAG_TOKEN, case.tok)
    if not rec_found(case):
        return refused(TAG_BOLE, INNER_MISSING)
    if case.lookup_fail:
        return refused(TAG_BOLE, INNER_INTERNAL)
    rec = case.rec
    borrowed = total_word(rec["a"], rec["ia"], div)
    supplied = total_word(rec["b"], rec["ib"], div)
    if case.real:
        r = curve(rec, ratio_or_zero(rec, div), div) // E10
        one = util_result(rec, div)
        uw = (one[0], one[1] // E10 if not one[0] else one[1])
        two = None if uw[0] else util_result(rec, div)
        uf = two and (two[0], float(two[1]) / 1e14 if not two[0] else two[1])
    else:
        r, uw, uf = case.r, case.uw, case.uf
    if uw[0] or uf[0]:
        return refused(TAG_BOLE, INNER_INTERNAL)
    words = (r, supply_rate(r, uf[1], case.c), rec["bal"], uw[1], rec["px"], rec["ltv"] // E10 if rec["tag"] & MASK[4] == 1 else 0, supplied, borrowed)
    events.append(("alloc", OUTPUT_SIZE))
    if case.oom == 1:
        return ("panic", (1, OUTPUT_SIZE), div.log, tuple(events), "panic")
    events.append(("alloc", 0x20))
    if case.oom == 2:
        return ("panic", (8, 0x20), div.log, tuple(events), "panic")
    data = output_bytes(words)
    poke(ALLOC_ONE, data)
    poke(ALLOC_TWO, struct.pack("<Q", 0x100))
    events.extend((("free", ALLOC_TWO, 0x20), ("bytes", OUTPUT_SIZE)))
    total = total_gas(case.n, case.out_len)
    if total > case.gas:
        events.append(("free_bytes", ALLOC_ONE, case.out_len))
        poke(OUT, bytes(16) + struct.pack("<Q", 1 << 63))
        return result("starved after output")
    poke(OUT, struct.pack("<QQQQQ", VTABLE, ALLOC_ONE, case.out_len, DATA_WORD, total))
    return result("ok")


def value_address(case):
    if case.shape == "deep":
        return NODES + 2 * NODE_STRIDE
    return NODES + REC_SIZE * (3 if case.tok >= 3 else 0)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        statics = memory.statics
        machine.calls = {DECODE: self.on_decode, FORMAT: self.on_format, DROP: self.on_drop, RATE_INT: self.on_rate, UTIL_WORD: self.on_util_word}
        hooks = {SLOT_DIV: self.on_div, SLOT_MEMCMP: self.on_memcmp, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free, SLOT_ALLOC_FAIL: self.on_alloc_fail,
                 SLOT_BYTES: self.on_bytes, SLOT_UNWRAP: self.on_panic, SLOT_INDEX: self.on_panic, SLOT_OVERFLOW: self.on_panic}
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        machine.slots[MARK_LOOKUP] = self.on_lookup_fail
        machine.slots[MARK_UTIL] = self.on_util_f64
        machine.slots[MARK_DROP_BYTES] = self.on_drop_bytes
        statics[SLOT_WRAP] = WRAP
        self.case = None
        self.log = []
        self.events = []
        self.allocs = 0

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        raise Panicked("panic helper")

    def on_alloc_fail(self, machine):
        raise Panicked("%d %d" % (machine.regs[RDI], machine.regs[RSI]))

    def on_div(self, machine):
        regs = machine.regs
        num, den = regs[RDI] | regs[RSI] << 64, regs[RDX] | regs[RCX] << 64
        index = len(self.log)
        self.log.append((num, den))
        q = self.case.faults[index] if index in self.case.faults else num // den
        regs[RAX], regs[RDX] = low(q), high(q)
        machine.keep_rdx = True

    def on_memcmp(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 20, "memcmp length")
        self.expect(regs[RDI] == ADDRESS_CONST, "memcmp left side")
        left = machine.memory.bytes_at(regs[RDI], 20)
        right = machine.memory.bytes_at(regs[RSI], 20)
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def on_decode(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == INPUT_DATA, "decode pointer")
        self.expect(regs[RSI] == self.case.n, "decode length")
        regs[RAX] = 0x101 if self.case.ok else 0x1FE
        regs[RDX] = self.case.tok
        machine.keep_rdx = True

    def on_format(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.expect(regs[RDX] & MASK[4] == 0, "format flag")
        tag = memory.read(regs[RSI], 2)
        payload = memory.read(regs[RSI] + 8, 8) if tag == TAG_TOKEN else memory.read(regs[RSI] + 2, 1)
        self.events.append(("format", tag, payload))
        for index, value in enumerate(FORMATTED):
            memory.write(regs[RDI] + 8 * index, 8, value)
        regs[RAX] = regs[RDI]

    def on_drop(self, machine):
        self.events.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_alloc(self, machine):
        regs = machine.regs
        self.allocs += 1
        self.events.append(("alloc", regs[RDI]))
        regs[RAX] = 0 if self.case.oom == self.allocs else ALLOC_ONE if self.allocs == 1 else ALLOC_TWO

    def on_free(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] & MASK[4] == 0, "free flags")
        self.events.append(("free", regs[RDI], regs[RSI]))

    def on_bytes(self, machine):
        regs = machine.regs
        memory = machine.memory
        cap, ptr, size = (memory.read(regs[RSI] + 8 * index, 8) for index in range(3))
        self.expect(cap == OUTPUT_SIZE and ptr == ALLOC_ONE and size == OUTPUT_SIZE, "vector words")
        self.events.append(("bytes", size))
        for index, value in enumerate((VTABLE, ptr, self.case.out_len, DATA_WORD)):
            memory.write(regs[RDI] + 8 * index, 8, value)

    def on_drop_bytes(self, machine):
        regs = machine.regs
        self.expect(machine.memory.read(regs[RDI], 8) == DATA_WORD, "bytes drop data")
        self.events.append(("free_bytes", regs[RSI], regs[RDX]))

    def on_rate(self, machine):
        self.expect(machine.regs[RDI] == value_address(self.case), "rate record")
        machine.regs[RAX] = self.case.r

    def on_util_word(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.expect(regs[RSI] == value_address(self.case), "utilization record")
        err, value = self.case.uw
        memory.write(regs[RDI], 1, err)
        if err:
            memory.write(regs[RDI] + 1, 1, value)
        else:
            memory.write(regs[RDI] + 8, 8, value)

    def on_util_f64(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.expect(regs[RSI] == value_address(self.case), "utilization record")
        err, value = self.case.uf
        memory.write(regs[RDI], 1, err)
        if err:
            memory.write(regs[RDI] + 1, 1, value)
        else:
            memory.write(regs[RDI] + 8, 8, to_bits(value))

    def on_lookup_fail(self, machine):
        machine.memory.write(machine.regs[RDI], 2, 0x0901)

    def put_rec(self, at, rec):
        memory = self.machine.memory
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF for index in range(REC_SIZE)))
        for offset, value in ((0, rec["tag"]), (8, rec["ltv"]), (0x10, rec["px"]), (0x18, rec["bal"]), (0x40, rec["a"]), (0x58, rec["ia"]), (0x60, rec["b"]), (0x78, rec["ib"]),
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

    def set_node(self, at, keys, children=(), stale=None):
        memory = self.machine.memory
        memory.write(at + SET_LEN, 2, len(keys))
        for slot in range(11):
            key = keys[slot] if slot < len(keys) else (stale if stale is not None else 0xFFFFFF00 + slot)
            memory.put_bytes(at + SET_KEY_AT + 20 * slot, key.to_bytes(20, "big"))
        for slot, child in enumerate(children):
            memory.write(at + SET_EDGE_AT + 8 * slot, 8, child)

    def set_state(self, case):
        memory = self.machine.memory
        if case.set_shape == "absent":
            memory.write(SET_ROOT, 8, 0)
            memory.write(SET_ROOT + 8, 8, 0xFEED)
            return
        keys = sorted(case.keys)
        if case.set_shape == "leaf":
            self.set_node(SET_NODES, keys, stale=ADDRESS)
            memory.write(SET_ROOT, 8, SET_NODES)
            memory.write(SET_ROOT + 8, 8, 0)
            return
        left, right = SET_NODES + SET_NODE_STRIDE, SET_NODES + 2 * SET_NODE_STRIDE
        if case.set_shape == "deep left":
            # The root key sits above the address, so the walk must take the first edge.
            self.set_node(left, keys, stale=ADDRESS)
            self.set_node(right, [ADDRESS + 8], stale=ADDRESS)
            self.set_node(SET_NODES, [ADDRESS + 5], (left, right))
        else:
            self.set_node(left, [ADDRESS - 3, ADDRESS - 2], stale=ADDRESS)
            self.set_node(right, keys, stale=ADDRESS)
            self.set_node(SET_NODES, [ADDRESS - 1], (left, right))
        memory.write(SET_ROOT, 8, SET_NODES)
        memory.write(SET_ROOT + 8, 8, 1)

    def tree_state(self, case):
        memory = self.machine.memory
        memory.write(MAP, 8, case.c)
        tok, rec = case.tok, case.rec
        decoy = dict(rec, a=rec["a"] ^ 0x55, ia=rec["ia"] ^ 0x33, b=rec["b"] ^ 0x77, ib=rec["ib"] ^ 0x11, px=rec["px"] ^ 0x99, bal=rec["bal"] ^ 0xAA, ltv=rec["ltv"] ^ E14, tag=rec["tag"] ^ 3)
        if case.shape == "empty":
            memory.write(MAP + 8, 8, 0)
            memory.write(MAP + 0x10, 8, 0xFEED)
            return
        if case.shape == "deep":
            left, right = NODES + NODE_STRIDE, NODES + 2 * NODE_STRIDE
            self.node(left, [(tok - 2 & TOP, decoy), (tok - 1 & TOP, decoy)], stale=tok)
            self.node(right, [(tok, rec), (tok + 2, decoy)], stale=tok + 1)
            self.node(NODES, [(tok - 1 & TOP, decoy)], (left, right))
            memory.write(MAP + 8, 8, NODES)
            memory.write(MAP + 0x10, 8, 1)
            return
        if case.shape == "leaf":
            lows = [(tok - 3 + index & TOP, decoy) for index in range(3)] if tok >= 3 else []
            self.node(NODES, lows + [(tok, rec), (tok + 1, decoy)], stale=tok)
        elif case.shape == "miss":
            self.node(NODES, [(tok - 1 & TOP, decoy), (tok + 1, decoy)], stale=tok)
        else:
            self.node(NODES, [(tok - 1 & TOP, decoy)], stale=tok)
        memory.write(MAP + 8, 8, NODES)
        memory.write(MAP + 0x10, 8, 0)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x1000)))
        self.case, self.log, self.events, self.allocs = case, [], [], 0
        memory.write(CTX + 0x10, 8, META)
        memory.write(CTX + 0x38, 8, SET_ROOT)
        memory.write(CTX + 0x48, 8, OWNER)
        memory.write(META + 0x198, 8, case.count)
        memory.write(INPUT + 8, 8, INPUT_DATA)
        memory.write(INPUT + 0x10, 8, case.n)
        memory.write(VTABLE + 0x20, 8, MARK_DROP_BYTES)
        self.set_state(case)
        self.tree_state(case)
        machine.real = frozenset((LOOKUP, WRAP) + ((RATE_INT, UTIL_WORD, UTIL_F64) if case.real else ()))
        memory.statics[SLOT_LOOKUP] = MARK_LOOKUP if case.lookup_fail else LOOKUP
        memory.statics[SLOT_UTIL_F64] = UTIL_F64 if case.real else MARK_UTIL
        return bytes(memory.heap[:USED])

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        try:
            if case.kind == LOOKUP:
                machine.run(LOOKUP, {RDI: OUT, RSI: MAP, RDX: case.tok})
            else:
                value = machine.run(PRECOMPILE, {RDI: OUT, RSI: CTX, RDX: INPUT, RCX: case.gas})
                if value != OUT:
                    raise Halt("result pointer")
        except Panicked as panic:
            text = str(panic).split()
            return before, ("panic", (int(text[0]), int(text[1])) if len(text) == 2 and text[0].isdigit() else str(panic), self.log, tuple(self.events), "panic")
        return before, ("run", bytes(machine.memory.heap[:USED]), self.log, tuple(self.events), None)

    def window(self, start, stop, setup, result):
        """Run a row range with poisoned registers; return its decision record and result."""
        machine = self.machine
        machine.regs = [POISON] * 16
        machine.xmm = [POISON | POISON << 64] * 16
        setup(machine)
        pc = start
        trace = []
        for _ in range(100):
            if pc == stop:
                return tuple(trace), result(machine)
            row = machine.cache.get(pc)
            if row is None:
                row = decode(machine.read_code, pc)
                machine.cache[pc] = row
            if row.op in ("jcc", "cmov"):
                trace.append((row.va, machine.condition(row.cc)))
            pc = machine.step(row)
            if row.op == "ucomisd":
                trace.append((row.va, machine.cf, machine.zf, machine.pf))
            elif row.op == "cvttsd2si":
                trace.append((row.va, machine.regs[row.a[1]] == 1 << 63))
        raise Halt("window did not end")

    def tail_stage(self, bits):
        def setup(machine):
            machine.xmm[1] = bits | POISON << 64
            machine.regs[RSP] = STACK_TOP - 0x1000
        return self.window(TAIL[0], TAIL[1], setup, lambda machine: machine.regs[R14])


def same(got, want):
    return got[:4] == want[:4]


TAIL = (0x324C1D3, 0x324C285)
FLOAT_SEEDS = ((0, 0x7FEFFFFFFFFFFFFF), (0x7FF0000000000000, 0x7FF0000000000000), (0x7FF0000000000001, (1 << 63) - 1),
               (1 << 63, (1 << 63) | 0x7FEFFFFFFFFFFFFF), ((1 << 63) | 0x7FF0000000000000, (1 << 63) | 0x7FF0000000000000),
               ((1 << 63) | 0x7FF0000000000001, MASK[8]))
INTERIOR_POINTS = 8


def interior(lo, hi):
    return [lo + (hi - lo) * index // (INTERIOR_POINTS + 1) for index in range(1, INTERIOR_POINTS + 1)]


def merge_pieces(found):
    found.sort(key=lambda row: row[0])
    merged = []
    for lo, hi, trace in found:
        if merged and merged[-1][2] == trace and merged[-1][1] + 1 == lo:
            merged[-1] = (merged[-1][0], hi, trace)
        else:
            merged.append((lo, hi, trace))
    return merged


def split(run, seed):
    """Halve a range until both ends share one decision record."""
    stack = [seed]
    found = []
    runs = 0
    while stack:
        lo, hi = stack.pop()
        first = run(lo)
        last = run(hi) if hi != lo else first
        runs += 2
        if first == last:
            found.append((lo, hi, first))
            continue
        middle = (lo + hi) // 2
        stack.append((middle + 1, hi))
        stack.append((lo, middle))
    return merge_pieces(found), runs


def tail_rows(harness):
    rows = []
    runs = 0
    machine = harness.machine
    machine.memory.reset(USED)
    for seed in FLOAT_SEEDS:
        pieces, count = split(lambda bits: harness.tail_stage(bits)[0], seed)
        runs += count
        for lo, hi, trace in pieces:
            for bits in [lo, hi] + (interior(lo, hi) if hi > lo else []):
                got = harness.tail_stage(bits)
                if got[0] != trace:
                    raise EvidenceError("interior point left its piece: %#x" % bits)
                if got[1] != tail(to_float(bits)):
                    raise EvidenceError("tail mismatch at %#x: %#x" % (bits, got[1]))
            rows.append(("%#x" % lo, "%#x" % hi, harness.tail_stage(lo)[1], harness.tail_stage(hi)[1], len(trace)))
    return rows, runs


def base_records():
    rows = [
        ("empty market", record()),
        ("half used", record(a=50, b=100)),
        ("at the bend", record(a=80, b=100)),
        ("above the bend", record(a=90, b=100, ltv=5 * 10 ** 13, tag=1, px=1234, bal=77)),
        ("index above one", record(a=10 ** 6, ia=E14 + 3, b=2 * 10 ** 6, ib=E14 + 7, ltv=8 * 10 ** 13, tag=1, px=9, bal=5)),
        ("borrow rounds up", record(a=1, ia=E14 + 1, b=3, ib=E14)),
        ("no supply with debt", record(a=7, b=0)),
        ("borrow over supply", record(a=3, b=2)),
        ("ratio cut", record(a=184468, b=1)),
        ("borrow product past the guard", record(a=TOP, ia=TOP, b=10)),
        ("supply product past the guard", record(a=10, b=TOP, ib=TOP)),
        ("index zero borrow", record(a=5, ia=0, b=5)),
        ("index zero supply", record(a=5, b=5, ib=0)),
        ("wide rates", record(a=99, b=100, mn=2 * 10 ** 13, mx=TOP, kr=3 * 10 ** 13, k=10 ** 13)),
        ("inverted config", record(a=20, b=100, mn=9 * 10 ** 13, mx=10 ** 13, kr=5 * 10 ** 13, k=5 * 10 ** 13)),
    ]
    return rows


GUARD_LEFT = 0x5AF3107A4000
F64_MAX = 1.7976931348623157e308


def named_cases():
    out = []
    add = out.append
    for shape in ("leaf", "deep", "deep left"):
        add(Case("blocked " + shape, keys=(ADDRESS, ADDRESS + 1), set_shape=shape))
        add(Case("other keys " + shape, keys=(ADDRESS + 1, ADDRESS + 2), set_shape=shape))
        add(Case("lower key only " + shape, keys=(ADDRESS - 1,), set_shape=shape))
    add(Case("blocked last", keys=(ADDRESS - 2, ADDRESS - 1, ADDRESS), set_shape="leaf"))
    add(Case("blocked middle", keys=(ADDRESS - 1, ADDRESS, ADDRESS + 1), set_shape="leaf"))
    add(Case("blocked second node", keys=(ADDRESS, ADDRESS + 4), set_shape="deep"))
    add(Case("empty set node", keys=(), set_shape="leaf"))
    add(Case("full set node", keys=tuple(ADDRESS + 1 + index for index in range(11)), set_shape="leaf"))
    add(Case("full below", keys=tuple(ADDRESS - 11 + index for index in range(11)), set_shape="leaf"))
    add(Case("high key byte", keys=(1 << 152, 1 << 153), set_shape="leaf"))
    add(Case("low looking high key", keys=((1 << 152) + ADDRESS,), set_shape="leaf"))
    add(Case("zero address key", keys=(0,), set_shape="leaf"))
    for n in (0, 1, 31, 32, 33, 64, 1999, 2000, 2001, 2002, 4000, 1 << 20, 1 << 59, TOP):
        add(Case("length %d" % n, n=n, gas=TOP))
    for n in (0, 32, 2000):
        base = gas_in(n)
        for gas in (0, base - 1, base, base + 1):
            add(Case("base gas %d %d" % (n, gas), n=n, gas=gas))
        full = total_gas(n, OUTPUT_SIZE)
        for gas in (full - 1, full, full + 1):
            add(Case("full gas %d %d" % (n, gas), n=n, gas=gas))
    add(Case("doc cost call", n=32, gas=10504))
    add(Case("output length 0", out_len=0, gas=1000 + 33 * 32))
    add(Case("output one more", out_len=OUTPUT_SIZE + 1))
    add(Case("output wide", out_len=(TOP // 33), gas=TOP))
    add(Case("output wide minus", out_len=(TOP // 33) - 100, gas=TOP))
    add(Case("output wide wraps", out_len=TOP // 33 + 1, gas=TOP))
    add(Case("output sum wraps", out_len=TOP // 33, n=2000, gas=TOP))
    add(Case("output sum tops", out_len=TOP // 33, n=0, gas=TOP - 1))
    add(Case("decode failure", ok=False))
    add(Case("decode failure beats token", ok=False, tok=100))
    add(Case("decode failure out of memory", ok=False, oom=1))
    add(Case("gas beats decode", ok=False, gas=1))
    for tok, count in ((9, 10), (10, 10), (11, 10), (0, 0), (0, 1), (1, 1), (TOP, TOP), (TOP - 1, TOP), (1 << 63, 1 << 63), ((1 << 63) - 1, 1 << 63), (1 << 32, 2)):
        add(Case("token %#x of %#x" % (tok, count), tok=tok, count=count))
    add(Case("token check beats record", tok=10, count=10, shape="empty"))
    for shape in ("empty", "miss", "below"):
        add(Case("record " + shape, shape=shape))
    add(Case("record deep", shape="deep"))
    add(Case("record first slot", tok=1))
    add(Case("lookup refuses", lookup_fail=True))
    add(Case("lookup refuses after inline hit", lookup_fail=True, shape="deep"))
    add(Case("first allocation fails", oom=1))
    add(Case("second allocation fails", oom=2))
    add(Case("utilization word fails", uw=(1, 3)))
    add(Case("utilization word fails 2", uw=(1, 2)))
    add(Case("utilization f64 fails", uf=(1, 3)))
    add(Case("both fail", uw=(1, 3), uf=(1, 2)))
    rec = record(a=7 * 10 ** 15, ia=E14 + 12345, b=9 * 10 ** 15, ib=E14 + 67, ltv=8123456789012, tag=1, px=0x1122334455667788, bal=0x99AABBCCDDEEFF01)
    add(Case("all words", rec=rec, r=0x10203, uw=(0, 0x40506), uf=(0, 0.75), c=2 * 10 ** 13))
    add(Case("tag two no ltv", rec=dict(rec, tag=2)))
    add(Case("tag zero no ltv", rec=dict(rec, tag=0)))
    add(Case("tag high word set", rec=dict(rec, tag=1 | 1 << 32)))
    add(Case("tag 257", rec=dict(rec, tag=257)))
    for ltv in (0, 1, E10 - 1, E10, E10 + 1, 2 * E10 - 1, E14, TOP, TOP - 1, TOP - TOP % E10, TOP - TOP % E10 - 1):
        add(Case("ltv %d" % ltv, rec=record(tag=1, ltv=ltv)))
    for a, ia in ((1, E14), (1, E14 - 1), (1, E14 + 1), (E14, 1), (0, TOP), (TOP, 0), (TOP, TOP), (GUARD_LEFT << 1, 1 << 63), (1 << 63, GUARD_LEFT << 1), (E14, 1 << 64 - 1), (TOP, E14), (TOP, E14 - 1), (TOP, E14 + 1), (2, 5 * 10 ** 13), (3, 5 * 10 ** 13),
                  (1 << 48, 1 << 47), (1 << 47, GUARD_LEFT), (1 << 47, GUARD_LEFT - 1)):
        add(Case("borrow word %#x %#x" % (a, ia), rec=record(a=a, ia=ia)))
        add(Case("supply word %#x %#x" % (a, ia), rec=record(b=a, ib=ia)))
    for hi in (E14 - 1, E14, E14 + 1):
        left = hi << 64
        pair = (left // TOP + 1, TOP)
        add(Case("borrow pair %d" % hi, rec=record(a=pair[0], ia=pair[1])))
        add(Case("supply pair %d" % hi, rec=record(b=pair[0], ib=pair[1])))
    add(Case("both pairs top", rec=record(a=TOP, ia=E14 - 1, b=TOP, ib=E14)))
    add(Case("quotient high bit", rec=record(a=1 << 63, ia=E14, b=(1 << 63) + 1, ib=E14)))
    for r, u, c in ((10000, 1.0, 0), (10000, 0.5, 0), (10000, 0.5, 10 ** 13), (10000, 0.5, E14), (10000, 0.5, 2 * E14), (10000, 0.5, 3 * E14), (0, 0.5, 0), (10000, 0.0, 0), (1844674407, 1.0, 0),
                    ((1 << 31) - 1, 1.0, 0), (1 << 31, 1.0, 0), ((1 << 31) + 1, 1.0, 0), ((1 << 32) - 1, 1.0, 0), (1 << 32, 1.0, 0), ((1 << 32) + 7, 1.0, 0), (TOP, 1.0, 0),
                    (10000, 1e300, 0), (2000000000, 1e300, 0), (2000000000, 1e308, E14 * 0), (2000000000, -1e300, 0), (10000, 1e15, 0), (10000, 1.8446744073709551e15, 0), (10000, 1.8446744073709552e15, 0), (10000, 2e15, 0),
                    (1, 1.8446744073709550e19, 0), (1, 18446744073709549568.0, 0), (1, 18446744073709551616.0, 0), (1, 18446744073709549568.0 * 2, 0), (1, 9223372036854775808.0, 0), (1, 9223372036854774784.0, 0), (1, 9223372036854777856.0, 0), (1, 0.9999999999, 0), (1, 1.0000000001, 0),
                    (1, F64_MAX, 0), (1, -F64_MAX, 0), (10000, math.inf, 0), (10000, -math.inf, 0), (10000, math.nan, 0), (0, math.inf, 0), (10000, 0.5, TOP), (10000, -0.5, 2 * E14), (10000, 0.5, 1 << 63), (10000, 0.5, (1 << 53) + 1), (10000, 0.5, (1 << 63) + 1025), (10000, 0.5, (1 << 32)), (10000, 0.5, 0xFFFFFFFF), (10000, 0.5, 0x100000000 | 0xF0000000)):
        add(Case("supply %d %r %d" % (r, u, c), r=r, uf=(0, u), c=c, uw=(0, 9)))
    for name, rec in base_records():
        for c in (0, 10 ** 13, E14, 2 * E14):
            add(Case("real %s c=%d" % (name, c), rec=rec, c=c, real=True))
    for shape in ("leaf", "miss", "below", "deep", "empty"):
        for tok in (1, 5):
            add(Case("lookup %s %d" % (shape, tok), kind=LOOKUP, shape=shape, tok=tok))
    return out


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state


def draw(stream):
    kind = next(stream) % 6
    raw = next(stream)
    if kind == 0:
        return raw
    if kind == 1:
        return raw >> (next(stream) % 64)
    if kind == 2:
        return E14 + (raw >> 40)
    if kind == 3:
        return raw % (2 * E14)
    if kind == 4:
        return raw % 1000
    return (1 << (next(stream) % 64)) + next(stream) % 3 - 1 & TOP


def draw_rec(stream):
    return record(a=draw(stream), ia=draw(stream), b=draw(stream), ib=draw(stream), tag=1 + next(stream) % 2, ltv=draw(stream), px=draw(stream), bal=draw(stream),
                  mn=draw(stream), mx=draw(stream), kr=draw(stream), k=draw(stream))


def vector_cases(count):
    stream = lcg(0x812)
    cases = []
    for index in range(count):
        rec = draw_rec(stream)
        n = next(stream) % 3000
        gas = total_gas(n, OUTPUT_SIZE) + next(stream) % 3 - 1 if next(stream) % 4 == 0 else TOP
        if index % 3 == 0:
            cases.append(Case("vector %d" % index, rec=rec, n=n, gas=gas, c=draw(stream), real=True))
        else:
            bits = next(stream) if next(stream) % 3 == 0 else to_bits((next(stream) % (1 << 40)) / (1 << 40))
            cases.append(Case("vector %d" % index, rec=rec, n=n, gas=gas, c=draw(stream), r=draw(stream), uw=(0, draw(stream)), uf=(0, to_float(bits))))
    return cases


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before)
        if not same(got, want):
            raise EvidenceError("case disagrees with the rule list: %s" % case.name + diff_text(got, want))
        outcomes.append((got, want[4]))
    return outcomes


def diff_text(got, want):
    if got[0] != want[0]:
        return " form %r %r" % (got[0], want[0])
    if got[1] != want[1]:
        if isinstance(got[1], bytes):
            at = next(index for index in range(len(got[1])) if got[1][index] != want[1][index])
            return " heap +%#x got %s want %s" % (at, got[1][at:at + 8].hex(), want[1][at:at + 8].hex())
        return " value %r %r" % (got[1], want[1])
    if got[2] != want[2]:
        return " divides %r %r" % (got[2], want[2])
    return " events %r %r" % (got[3], want[3])


def reciprocal_rows():
    spare = MUL_E10 * E10 - (1 << SHIFT_E10)
    worst = TOP * spare
    if spare <= 0 or worst >= 1 << SHIFT_E10:
        raise EvidenceError("reciprocal bound fails")
    return [("%#x" % MUL_E10, SHIFT_E10, spare, TOP, worst, 1 << SHIFT_E10)]


def rate_bound_rows():
    largest = TOP // E10
    if largest >= 1 << 31:
        raise EvidenceError("rate word can reach the sign bit")
    return [("largest rate/1e10", largest), ("first 32 bit negative", 1 << 31), ("margin", (1 << 31) - largest)]


def gas_rows():
    rows = []
    for n in (0, 4, 32, 36, 64, 2000):
        rows.append((n, gas_in(n), total_gas(n, OUTPUT_SIZE), DOC_BASE + DOC_PER_BYTE * (n + OUTPUT_SIZE)))
    return rows


def double_read(image, va):
    return struct.unpack("<d", bytes(image.blob[image.offset(va):image.offset(va) + 8]))[0]


def constant_rows(image):
    rows = []
    for name, va, want in (("minus 1e14", F_RESERVE, -1e14), ("one", F_ONE, 1.0), ("2^64", F_TWO64, 18446744073709551616.0), ("2^64-2048", F_TOP, 18446744073709549568.0), ("2^63", F_TWO63, 9223372036854775808.0)):
        value = double_read(image, va)
        if value != want:
            raise EvidenceError("constant moved: " + name)
        rows.append((name, "%#x" % va, repr(value), "%#x" % to_bits(value)))
    data = bytes(image.blob[image.offset(ADDRESS_CONST):image.offset(ADDRESS_CONST) + 20])
    if int.from_bytes(data, "big") != ADDRESS:
        raise EvidenceError("address constant moved")
    rows.append(("precompile address", "%#x" % ADDRESS_CONST, data.hex(), "20 bytes"))
    return rows


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


def immediate_rows(image, table):
    """Immediates read from the decoded rows, one line for each number the rule list uses."""
    wanted = {(0x324BEC6, 0x7D0): "length cap", (0x324BEDA, 0x3E8): "gas base", (0x324C442, 0x21): "gas per output byte", (0x324BED2, 5): "shift for 33 * length"}
    rows = []
    found = {row.va: row for row in table}
    for (va, value), name in sorted(wanted.items()):
        row = found.get(va)
        data = bytes(image.blob[image.offset(va):image.offset(va) + row.size])
        if value not in (row.a[1] if row.a and row.a[0] == "i" else None, row.b[1] if row.b and row.b[0] == "i" else None, row.imm if hasattr(row, "imm") else None):
            raise EvidenceError("immediate moved at %#x" % va)
        rows.append((name, "%#x" % va, data.hex(), value))
    return rows


def text_at(image, va, size):
    start = image.offset(va)
    return bytes(image.blob[start:start + size]).decode()


def arm_text(image, arm):
    """Read `lea text,%rsi; mov $len,%edx` from a Display arm of the two common shapes."""
    start = image.offset(arm)
    data = bytes(image.blob[start:start + 40])
    pattern = bytes.fromhex("488b3e488b4608488b4018488d35")
    if data.startswith(pattern):
        at = len(pattern)
    else:
        raise EvidenceError("unknown Display arm shape at %#x" % arm)
    disp = struct.unpack_from("<i", data, at)[0]
    if data[at + 4] != 0xBA:
        raise EvidenceError("no length in Display arm at %#x" % arm)
    return text_at(image, arm + at + 4 + disp, struct.unpack_from("<I", data, at + 5)[0])


def tag_arm(image, tag):
    return E0_DISPLAY + struct.unpack_from("<i", image.blob, image.offset(E0_DISPLAY + 4 * tag))[0]


def text_rows(image):
    rows = [("0xea", arm_text(image, tag_arm(image, TAG_TOKEN)))]
    size = image.blob[image.offset(PREFIX_E1)]
    rows.append(("0xe1 prefix", text_at(image, PREFIX_E1 + 1, size)))
    start = image.offset(INNER_DISPLAY_ARM)
    data = bytes(image.blob[start:start + 24])
    if data[:11] != bytes.fromhex("488b3e488b4608488b4018"):
        raise EvidenceError("inner arm moved")
    rows.append(("0xe1 inner 0xa", arm_text(image, INNER_DISPLAY_ARM)))
    return rows


def holder_rows(image):
    """Who reaches the function: RELATIVE slots holding its address, and direct rel32 calls or jumps at it."""
    slots = sorted(slot for slot, value in image.relative().items() if value == PRECOMPILE)
    if tuple(slots) != TABLE_SLOTS:
        raise EvidenceError("table slots moved: %s" % [hex(slot) for slot in slots])
    va, text = image.text_bytes()
    direct = [va + match.start() for match in re.finditer(rb"[\xe8\xe9]", text)
              if match.start() + 5 <= len(text) and va + match.start() + 5 + struct.unpack_from("<i", text, match.start() + 1)[0] == PRECOMPILE]
    return [("slot", "%#x" % slot) for slot in slots] + [("direct", "%#x" % site) for site in direct] + [("direct_count", len(direct))]


def output_rows(harness):
    """One probe with distinct source values, so the word order comes from the run and not from the rule list."""
    rec = record(a=3 * 10 ** 15, ia=E14 + 11, b=5 * 10 ** 15, ib=E14 + 13, tag=1, ltv=7 * 10 ** 13, px=0x1020304, bal=0x5060708)
    case = Case("probe", rec=rec, r=2000, uw=(0, 3000), uf=(0, 0.75), c=2 * 10 ** 13)
    _, got = harness.run(case)
    words = [struct.unpack_from(">Q", got[1], ALLOC_ONE - HEAP_BASE + 32 * index + 24)[0] for index in range(WORDS)]
    names = ("rate word from 0x37412a0 (rate/1e10)", "trunc(rate word * utilization f64 * (1 - owner +0xc8 / 1e14)), saturating", "record +0x18", "utilization word from 0x3741010 (ratio/1e10)", "record +0x10",
             "record +8 / 1e10 when record +0 (32 bits) is 1, else 0", "floor(record +0x60 * +0x78 / 1e14), 0 past the guard", "floor(record +0x40 * +0x58 / 1e14), 0 past the guard")
    return [(index, "%#x" % (32 * index + 24), words[index], names[index]) for index in range(WORDS)]


def rounding_rows(harness):
    """Floor here against the ceiling in the rate path, and the double floor of the supply word."""
    rows = []
    for a, ia in ((1, E14 + 1), (3, E14 // 2), (10 ** 6, E14 + 3), (5, E14)):
        rec = record(a=a, ia=ia, b=1)
        got = harness.run(Case("probe", rec=rec))[1]
        word = struct.unpack_from(">Q", got[1], ALLOC_ONE - HEAP_BASE + 32 * 7 + 24)[0]
        rows.append(("borrowed word", a, ia, word, -(-(a * ia) // E14)))
    for rate, u, c in ((1234567890123, 0.5, 0), (99999999999, 1.0, 0), (19999999999, 0.75, 10 ** 13)):
        r = rate // E10
        got = harness.run(Case("probe", r=r, uf=(0, u), c=c))[1]
        word = struct.unpack_from(">Q", got[1], ALLOC_ONE - HEAP_BASE + 32 + 24)[0]
        rows.append(("supply word", rate, "%r %d" % (u, c), word, int(rate * u * (1 - c / E14) / E10)))
    return rows


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
            if not same(got, spec_run(case, before)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


EXPECTED_SURVIVORS = {
    (0x324BFDB, "immediate"): "low byte of the text word stored at +5; the next store at +0 overwrites bytes 5 to 7, so the edit cannot reach the text",
    (0x324C1D8, "immediate"): "low bit of the absolute value mask; the threshold it meets ends in an odd word, so clearing that bit never changes the jg",
    (0x324C20F, "condition"): "the first clamp below zero: the conversion after it floors negatives to 0 by itself, so both paths give the same word",
    (0x324C219, "condition"): "the clamp above 2^64: the compare with 2^64-2048 after the conversion saturates by itself, so both paths give the same word",
    (0x324C25D, "immediate"): "sar 62 for sar 63: the mask loses only bit 0 of a value above 2^63, and a double there is a multiple of 2048",
    (0x324C4BC, "immediate"): "the product saturation value: gas so far is at least 1000, so the add carries and the cmov gives u64::MAX for -1 or -2",
}


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    extra = vector_cases(120)
    plain = cases + extra
    for target in TARGETS:
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(harness, plain)
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


def analyse(image, mutate=True, vectors=300):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    pieces, runs = tail_rows(harness)
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, constants=constant_rows(image), immediates=immediate_rows(image, table[PRECOMPILE]), texts=text_rows(image),
                  holders=holder_rows(image), reciprocals=reciprocal_rows(), bounds=rate_bound_rows(), gas=gas_rows(), output=output_rows(harness), rounding=rounding_rows(harness), pieces=pieces, tail_runs=runs)
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    got, stamp = outcome
    return "%#x" % case.kind, case.name, stamp, hashlib.sha256(repr((got[0], got[1], got[2], got[3])).encode()).hexdigest()[:16], len(got[2]), len(got[3])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("constants.tsv", ("name", "address", "value", "bits"), result["constants"])
    tsv("immediates.tsv", ("name", "site", "bytes", "value"), result["immediates"])
    tsv("texts.tsv", ("error", "text"), result["texts"])
    tsv("holders.tsv", ("kind", "value"), result["holders"])
    tsv("reciprocals.tsv", ("multiplier", "shift", "spare", "largest_input", "worst_error", "two_to_shift"), result["reciprocals"])
    tsv("rate-word-bound.tsv", ("name", "value"), result["bounds"])
    tsv("gas-table.tsv", ("input_length", "base_gate", "total_for_256_byte_output", "docs_formula"), result["gas"])
    tsv("output-map.tsv", ("word", "last_8_bytes_at", "probe_value", "source"), result["output"])
    tsv("rounding-samples.tsv", ("word", "a", "b", "precompile", "other_rule"), result["rounding"])
    tsv("tail-pieces.tsv", ("low_bits", "high_bits", "at_low", "at_high", "decisions"), result["pieces"])
    tsv("outcomes.tsv", ("entry", "case", "result", "digest", "divides", "events"), [describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"], "tail_pieces": len(result["pieces"]), "tail_runs": result["tail_runs"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"), "survived": sum(1 for r in rows if r[2] == "survived")}
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
