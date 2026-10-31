#!/usr/bin/env python3
"""Pin the node #94 user outcome amount gates and leg builders from ELF bytes.

Split, merge, merge question and negate reach their amount rules through 0x37250d0, 0x3724f20,
0x37253c0 and 0x3725ab0; 0x3726750 and 0x3726ed0 build the legs for split and negate. The real bytes run
over real hash table and B-tree layouts, a separately written specification predicts every run, and
every reached conditional row is mutated. No objdump or readelf output is parsed and the binary is
never executed. Standard library only.

    python3 tools/outcome_user_amounts.py --out <dir>
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
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}


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
        elif op in ("shld", "shrd"):
            count = (row.target if op == "shld" else self.regs[RCX]) & 63
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








FILL = 0xCC

SPLIT = 0x37250D0
MERGE = 0x3724F20
MERGE_ALL = 0x37253C0
NEGATE = 0x3725AB0
SPLIT_LEGS = 0x3726750
NEGATE_LEGS = 0x3726ED0
PAIR_HELPER = 0x385C150
TWO_BALANCES = 0x3C18150
TREE_FIND = 0x3394620
SIDE_HELPER = 0x3C18FB0
TARGETS = (SPLIT, MERGE, MERGE_ALL, NEGATE, SPLIT_LEGS, NEGATE_LEGS, PAIR_HELPER)
NAMES = {SPLIT: "split_gate", MERGE: "merge_gate", MERGE_ALL: "merge_question_gate", NEGATE: "negate_gate", SPLIT_LEGS: "split_legs",
         NEGATE_LEGS: "negate_legs", PAIR_HELPER: "pair_helper", TWO_BALANCES: "two_balances", TREE_FIND: "tree_find", SIDE_HELPER: "side_helper"}
SLOTS = {SPLIT: 0x5773840, MERGE: 0x5773878, MERGE_ALL: 0x5773868, NEGATE: 0x5773858, SPLIT_LEGS: 0x5773888, NEGATE_LEGS: 0x5773860}
REAL = frozenset((PAIR_HELPER, TWO_BALANCES, TREE_FIND, SIDE_HELPER))
MARK_BASE = 0x7700000000

HASH = 0x399C4A0
DROP = 0x3762510
SLOT_REGISTRY = 0x5774760
SLOT_CONVERT = 0x5774AF8
SLOT_HOLDER = 0x5773170
SLOT_RECORD = 0x5773190
SLOT_GROW16 = 0x5775750
SLOT_GROW24 = 0x5775740
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ALLOC_FAIL = 0x576E020
SLOT_PANIC_RDI = 0x576E470
SLOT_PANIC_RDX = 0x576DFC8
LOC_TOKEN_TABLE = 0x56F21F0
LOC_SPOT_TABLE = 0x5714C70
LOC_WEI_SUB = 0x56DFD90
OK_WORD = 0x186
BAD_WORD = 0x15C
TAG_NONE = 1 << 63

OUT = HEAP_BASE + 0x400
USER = HEAP_BASE + 0x700
AMOUNT = HEAP_BASE + 0x780
INPUT = HEAP_BASE + 0x800
REGISTRY = HEAP_BASE + 0x900
MAP = HEAP_BASE + 0xA00
ORIGIN = HEAP_BASE + 0xFF0
STATE = HEAP_BASE + 0x1000
OUTCOME_LOW = HEAP_BASE + 0x3C00
OUTCOME_CTRL = HEAP_BASE + 0x6000
QUESTION_LOW = HEAP_BASE + 0x6100
QUESTION_CTRL = HEAP_BASE + 0x9000
TOKENS = HEAP_BASE + 0x9100
TOKEN_WORDS = HEAP_BASE + 0xB800
SPOTS = HEAP_BASE + 0xBC00
BALANCE_NODES = HEAP_BASE + 0xC400
SET_NODES = HEAP_BASE + 0xF000
VECTOR = HEAP_BASE + 0x12000
ALLOCATED = HEAP_BASE + 0x16000
USED = 0x18000
BUCKETS = 64
OUTCOME_STRIDE = 0x90
QUESTION_STRIDE = 0x70
TOKEN_STRIDE = 0xE8
SPOT_STRIDE = 0x20
TOKEN_ROWS = 40
SPOT_ROWS = 40
USER_BYTES = bytes(range(0x51, 0x65))
HASH_FACTOR = 0x9E3779B97F4A7C15
OUT_SIZE = 0xB0
MAX_U64 = MASK[8]


def hash_of(key):
    return (key * HASH_FACTOR) & MASK[8]


class SpecPanic(Exception):
    pass


class Case:
    """One call: one of the six functions, the two tables, the balances and the amount answer."""

    def __init__(self, name="", kind=SPLIT, **fields):
        self.name = name
        self.kind = kind
        self.outcome = 7
        self.question = 3
        self.outcomes = {7: (11, 12, 100), 8: (13, 14, 100), 9: (15, 16, 100)}
        self.questions = {3: (7, (8, 9))}
        self.quotes = {}
        self.token_of = {}
        self.spot_lens = {}
        self.token_count = TOKEN_ROWS
        self.spot_count = SPOT_ROWS
        self.outcome_items = 5
        self.question_items = 5
        self.balances = {3: (100000, 0), 11: (50, 0), 12: (70, 0), 13: (60, 0), 14: (80, 0), 15: (90, 0), 16: (40, 0)}
        self.amount = 1000
        self.registry = None
        self.shape = "leaf"
        self.set_shape = "leaf"
        self.input = None
        self.__dict__.update(fields)

    def quote(self, spot):
        return self.quotes.get(spot, 3)

    def spot(self, token):
        return self.token_of.get(token, token)

    def side(self, token):
        """One side of the two-sided helper: (refused, quote token)."""
        if token >= self.token_count:
            raise SpecPanic(LOC_TOKEN_TABLE)
        if self.spot_lens.get(token, 1) != 1:
            return (True, None)
        spot = self.spot(token)
        if spot >= self.spot_count:
            raise SpecPanic(LOC_SPOT_TABLE)
        return (False, self.quote(spot))


class Spec:
    """The rules, written from the reading and independent of the evaluator."""

    def __init__(self, case):
        self.case = case
        self.events = []
        self.writes = {}
        self.vector_rows = []
        self.capacity = 0
        self.allocated = []
        self.next_block = ALLOCATED

    def word(self, at, value):
        self.writes[at] = (8, value & MAX_U64)

    def byte(self, at, value):
        self.writes[at] = (1, value)

    def avail(self, token):
        if token not in self.case.balances:
            return 0
        total, hold = self.case.balances[token]
        if total < hold:
            self.events.append(("record", 0, LOC_WEI_SUB))
            return 0
        return total - hold

    def holder(self):
        self.events.append(("holder",))

    def convert(self, token):
        amount = self.case.amount
        self.events.append(("convert", token))
        if amount == "bad":
            self.events.append(("drop", BAD_WORD))
            return None
        return amount

    def pair(self, record):
        first = self.case.side(record[0])
        second = self.case.side(record[1])
        if first[0] or second[0] or first[1] != second[1]:
            return None
        return first[1]

    def push(self, outcome, token):
        if len(self.vector_rows) == self.capacity:
            self.capacity = max(4, self.capacity * 2)
            self.events.append(("grow16", self.capacity))
        self.vector_rows.append((outcome, token))

    def free_vector(self):
        if self.capacity:
            self.events.append(("free", VECTOR, self.capacity * 16))

    def fail_small(self, status):
        self.byte(OUT, 1)
        self.byte(OUT + 1, status)

    def fail_big(self, status):
        self.word(OUT, TAG_NONE)
        self.byte(OUT + 8, status)

    def split(self):
        case = self.case
        outcome = case.outcome
        self.events.append(("registry", outcome))
        if case.registry == outcome:
            return self.fail_small(6)
        if case.outcome_items == 0 or outcome not in case.outcomes:
            return self.fail_small(8)
        record = case.outcomes[outcome]
        quote = self.pair(record)
        if quote is None:
            return self.fail_small(8)
        amount = self.convert(quote)
        if amount is None or amount % record[2]:
            return self.fail_small(1)
        self.holder()
        if self.avail(quote) < amount:
            return self.fail_small(2)
        self.byte(OUT, 0)
        self.word(OUT + 8, outcome)
        self.word(OUT + 0x10, quote)
        self.word(OUT + 0x18, amount)

    def merge(self):
        case = self.case
        outcome = case.outcome
        if case.outcome_items == 0 or outcome not in case.outcomes:
            self.word(OUT, 2)
            self.byte(OUT + 8, 8)
            return
        record = case.outcomes[outcome]
        quote = self.pair(record)
        if quote is None:
            self.word(OUT, 2)
            self.byte(OUT + 8, 8)
            return
        self.holder()
        first = self.avail(record[0])
        self.holder()
        second = self.avail(record[1])
        least = min(first, second)
        if record[2] == 0:
            self.word(OUT, 2)
            self.byte(OUT + 8, 8)
            return
        if case.amount is None:
            self.word(OUT, 0)
            return
        amount = self.convert(quote)
        if amount is None or amount % record[2]:
            self.word(OUT, 2)
            self.byte(OUT + 8, 1)
            return
        pieces = amount // record[2]
        if least < pieces:
            self.word(OUT, 2)
            self.byte(OUT + 8, 3)
            return
        self.word(OUT, 1)
        self.word(OUT + 8, amount)

    def members(self, question):
        return (question[0],) + tuple(sorted(question[1]))

    def merge_all(self):
        case = self.case
        if case.question_items == 0 or case.question not in case.questions:
            return self.fail_big(8)
        question = case.questions[case.question]
        if case.outcome_items == 0:
            return self.fail_big(8)
        least = None
        for outcome in self.members(question):
            if outcome not in case.outcomes:
                self.free_vector()
                return self.fail_big(8)
            token = case.outcomes[outcome][0]
            self.holder()
            have = self.avail(token)
            least = have if least is None else min(least, have)
            self.push(outcome, token)
        if case.amount is None:
            amount = least
        else:
            amount = self.convert(self.vector_rows[0][1])
            status = 1 if amount is None else 3 if least < amount else 0
            if status:
                self.free_vector()
                return self.fail_big(status)
        self.word(OUT, self.capacity)
        self.word(OUT + 8, VECTOR)
        self.word(OUT + 0x10, len(self.vector_rows))
        self.word(OUT + 0x18, question[0])
        self.word(OUT + 0x20, amount)

    def negate(self):
        case = self.case
        outcome = case.outcome
        if case.question_items == 0 or case.question not in case.questions:
            return self.fail_big(8)
        question = case.questions[case.question]
        if question[0] == outcome:
            return self.fail_big(5)
        if outcome not in question[1]:
            return self.fail_big(4)
        if case.outcome_items == 0 or outcome not in case.outcomes:
            return self.fail_big(8)
        token = case.outcomes[outcome][1]
        amount = self.convert(token)
        if amount is None:
            return self.fail_big(1)
        self.holder()
        if self.avail(token) < amount:
            return self.fail_big(3)
        for other in self.members(question):
            if other == outcome:
                continue
            if other not in case.outcomes:
                self.free_vector()
                return self.fail_big(8)
            self.push(other, case.outcomes[other][0])
        self.word(OUT, self.capacity)
        self.word(OUT + 8, VECTOR)
        self.word(OUT + 0x10, len(self.vector_rows))
        self.word(OUT + 0x18, outcome)
        self.word(OUT + 0x20, amount)
        self.word(OUT + 0x28, token)

    def block(self, size):
        at = self.next_block
        self.next_block += size
        self.events.append(("alloc", size))
        self.allocated.append(at)
        return at

    def split_legs(self):
        case = self.case
        outcome, quote, amount = case.input
        if case.outcome_items == 0 or outcome not in case.outcomes:
            self.byte(OUT, 4)
            self.word(OUT + 8, 4)
            return
        first, second, unit = case.outcomes[outcome]
        if unit > amount:
            self.word(OUT + 8, 3)
            return
        pieces = amount // unit
        debit = self.block(0x18)
        credit = self.block(0x30)
        self.blocks = ((debit, (outcome, quote, amount)), (credit, (outcome, first, pieces, outcome, second, pieces)))
        self.word(OUT + 8, 2)
        self.word(OUT + 0x70, 1)
        self.word(OUT + 0x78, debit)
        self.word(OUT + 0x80, 1)
        self.word(OUT + 0x88, 2)
        self.word(OUT + 0x90, credit)
        self.word(OUT + 0x98, 2)
        self.byte(OUT + 0xA0, 0)

    def negate_legs(self):
        case = self.case
        capacity, others, outcome, amount, token = case.input
        if amount == 0:
            self.word(OUT + 8, 3)
            if capacity:
                self.events.append(("free", VECTOR, capacity * 16))
            return
        rows = []
        grown = 0
        for other, tok in others:
            if len(rows) == grown:
                grown = max(4, grown * 2)
                self.events.append(("grow24", grown))
            rows.append((other, tok, amount))
        if capacity:
            self.events.append(("free", VECTOR, capacity * 16))
        debit = self.block(0x18)
        self.blocks = ((debit, (outcome, token, amount)), (ALLOCATED + 0x400 if grown else 8, tuple(cell for row in rows for cell in row)))
        self.word(OUT + 8, 2)
        self.word(OUT + 0x70, 1)
        self.word(OUT + 0x78, debit)
        self.word(OUT + 0x80, 1)
        self.word(OUT + 0x88, grown)
        self.word(OUT + 0x90, ALLOCATED + 0x400 if grown else 8)
        self.word(OUT + 0x98, len(rows))
        self.byte(OUT + 0xA0, 2)


SPEC_METHODS = {SPLIT: "split", MERGE: "merge", MERGE_ALL: "merge_all", NEGATE: "negate", SPLIT_LEGS: "split_legs", NEGATE_LEGS: "negate_legs"}


def spec_run(case):
    spec = Spec(case)
    spec.blocks = ()
    try:
        getattr(spec, SPEC_METHODS[case.kind])()
    except SpecPanic as error:
        return ("panic", error.args[0], tuple(spec.events))
    out = bytearray([FILL]) * OUT_SIZE
    for at, (size, value) in spec.writes.items():
        out[at - OUT:at - OUT + size] = value.to_bytes(size, "little")
    if case.kind == MERGE and case.amount is None and spec.writes.get(OUT) == (8, 0):
        out[8:16] = bytes(8)
    rows = tuple(spec.vector_rows) if spec.writes.get(OUT, (0, TAG_NONE))[1] not in (TAG_NONE,) and case.kind in (MERGE_ALL, NEGATE) else ()
    return ("value", bytes(out), tuple(spec.events), rows, tuple(spec.blocks))


def free_slot(control, digest):
    """The first empty slot along the triangular group probe."""
    position = digest & (BUCKETS - 1)
    stride = 0
    while True:
        for offset in range(16):
            at = (position + offset) & (BUCKETS - 1)
            if control[at] == 0xFF:
                return at
        stride += 16
        position = (position + stride) & (BUCKETS - 1)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = REAL
        machine.calls = {HASH: self.on_hash, DROP: self.on_drop}
        machine.slots = {}
        table = {SLOT_REGISTRY: self.on_registry, SLOT_CONVERT: self.on_convert, SLOT_HOLDER: self.on_holder, SLOT_RECORD: self.on_record,
                 SLOT_GROW16: self.on_grow16, SLOT_GROW24: self.on_grow24, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_free,
                 SLOT_ALLOC_FAIL: self.on_abort, SLOT_PANIC_RDI: self.on_panic_rdi, SLOT_PANIC_RDX: self.on_panic_rdx}
        for slot, hook in table.items():
            marker = MARK_BASE + slot
            machine.memory.statics[slot] = marker
            machine.slots[marker] = hook
        self.events = []
        self.case = None
        self.block = ALLOCATED
        self.blocks = []
        self.grown = VECTOR

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def read(self, addr, size=8):
        return self.machine.memory.read(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def on_hash(self, machine):
        self.expect(machine.regs[RDI] in (STATE + 0xF0, STATE + 0x120), "hash table")
        machine.regs[RAX] = hash_of(self.read(machine.regs[RSI]))

    def on_drop(self, machine):
        self.events.append(("drop", self.read(machine.regs[RDI], 2)))

    def on_registry(self, machine):
        self.expect(machine.regs[RDI] == STATE, "registry state")
        self.events.append(("registry", machine.regs[RSI]))
        registry = self.case.registry
        if registry is None:
            machine.regs[RAX] = 0
        else:
            self.word(REGISTRY + 0x30, registry)
            machine.regs[RAX] = REGISTRY

    def on_convert(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == STATE and regs[RCX] == AMOUNT, "convert arguments")
        self.events.append(("convert", regs[RDX]))
        amount = self.case.amount
        if amount == "bad":
            self.word(regs[RDI], BAD_WORD, 2)
        else:
            self.word(regs[RDI], OK_WORD, 2)
            self.word(regs[RDI] + 8, amount)

    def on_holder(self, machine):
        self.expect(machine.regs[RDI] == ORIGIN, "holder map")
        self.expect(machine.memory.bytes_at(machine.regs[RSI], 20) == USER_BYTES, "holder user")
        self.events.append(("holder",))
        machine.regs[RAX] = MAP

    def on_record(self, machine):
        self.events.append(("record", machine.regs[RDI], machine.regs[RSI]))

    def grow(self, machine, name, size):
        at = machine.regs[RDI]
        capacity = max(4, self.read(at) * 2)
        base = VECTOR if size == 16 else ALLOCATED + 0x400
        self.word(at, capacity)
        self.word(at + 8, base)
        self.events.append((name, capacity))

    def on_grow16(self, machine):
        self.grow(machine, "grow16", 16)

    def on_grow24(self, machine):
        self.grow(machine, "grow24", 24)

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        self.events.append(("alloc", size))
        at = self.block
        self.block += size
        self.blocks.append((at, size))
        machine.regs[RAX] = at

    def on_free(self, machine):
        self.expect(machine.regs[RDX] == 0, "free align")
        self.events.append(("free", machine.regs[RDI], machine.regs[RSI]))

    def on_abort(self, machine):
        raise Halt("abort stub")

    def on_panic_rdi(self, machine):
        raise Panicked(machine.regs[RDI])

    def on_panic_rdx(self, machine):
        raise Panicked(machine.regs[RDX])

    def install_table(self, entries, low, control_at, stride, write):
        memory = self.machine.memory
        memory.put_bytes(low, bytes([FILL]) * (control_at - low))
        control = bytearray([0xFF]) * (BUCKETS + 16)
        for key in sorted(entries, reverse=True):
            digest = hash_of(key)
            at = free_slot(control, digest)
            control[at] = digest >> 57
            if at < 16:
                control[BUCKETS + at] = digest >> 57
            entry = control_at - stride * (at + 1)
            self.word(entry, key)
            write(entry, entries[key])
        memory.put_bytes(control_at, bytes(control))

    def write_outcome(self, entry, record):
        self.word(entry + 0x28, record[0])
        self.word(entry + 0x50, record[1])
        self.word(entry + 0x88, record[2])

    def set_node(self, base, keys, parent, index, children):
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * 0xC8)
        self.word(base, parent)
        for slot in range(11):
            self.word(base + 8 + 8 * slot, keys[slot] if slot < len(keys) else (self.case.outcome if slot == len(keys) and not children and self.case.set_shape == "leaf" else 0x7777 + slot))
        self.word(base + 0x60, index, 2)
        self.word(base + 0x62, len(keys), 2)
        for slot, child in enumerate(children):
            self.word(base + 0x68 + 8 * slot, child)

    def write_set(self, entry, keys, cursor):
        keys = tuple(sorted(keys))
        if self.case.set_shape == "two" and len(keys) >= 3:
            cut = len(keys) // 2
            root = cursor
            left = root + 0xD0
            right = left + 0xD0
            self.set_node(root, keys[cut:cut + 1], 0, 0, (left, right))
            self.set_node(left, keys[:cut], root, 0, ())
            self.set_node(right, keys[cut + 1:], root, 1, ())
            self.word(entry + 0x40, root)
            self.word(entry + 0x48, 1)
            self.word(entry + 0x50, len(keys))
            return right + 0xD0
        self.set_node(cursor, keys, 0, 0, ())
        self.word(entry + 0x40, cursor if keys else 0)
        self.word(entry + 0x48, 0)
        self.word(entry + 0x50, len(keys))
        return cursor + 0xD0

    def write_questions(self, questions):
        cursor = [SET_NODES]

        def write(entry, record):
            self.word(entry + 0x38, record[0])
            cursor[0] = self.write_set(entry, record[1], cursor[0])

        self.install_table(questions, QUESTION_LOW, QUESTION_CTRL, QUESTION_STRIDE, write)

    def balance_node(self, base, keys, children):
        memory = self.machine.memory
        balances = self.case.balances
        memory.put_bytes(base, bytes([FILL]) * 0x1D0)
        for slot in range(11):
            key = keys[slot] if slot < len(keys) else 0
            self.word(base + 8 + 8 * slot, key)
            total, hold = balances[key] if slot < len(keys) else (0xBAD0 + slot, 0x10)
            self.word(base + 0x60 + 0x18 * slot, total)
            self.word(base + 0x68 + 0x18 * slot, hold)
            self.word(base + 0x70 + 0x18 * slot, 0xABAB)
        self.word(base + 0x16A, len(keys), 2)
        for slot, child in enumerate(children):
            self.word(base + 0x170 + 8 * slot, child)

    def write_balances(self):
        case = self.case
        keys = tuple(sorted(case.balances))
        self.word(MAP + 0x10, 0)
        self.word(MAP + 0x18, 0)
        if not keys:
            return
        if case.shape == "two" and len(keys) >= 3:
            cut = len(keys) // 2
            left = BALANCE_NODES + 0x200
            right = left + 0x200
            self.balance_node(BALANCE_NODES, keys[cut:cut + 1], (left, right))
            self.balance_node(left, keys[:cut], ())
            self.balance_node(right, keys[cut + 1:], ())
            self.word(MAP + 0x18, 1)
        else:
            self.balance_node(BALANCE_NODES, keys[:11], ())
        self.word(MAP + 0x10, BALANCE_NODES)

    def install(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        self.case = case
        self.events = []
        self.block = ALLOCATED
        self.blocks = []
        memory.put_bytes(OUT, bytes([FILL]) * (OUT_SIZE + 8))
        memory.put_bytes(USER, USER_BYTES)
        memory.put_bytes(ORIGIN, bytes([FILL]) * 0x2010)
        self.word(STATE + 0xD0, OUTCOME_CTRL)
        self.word(STATE + 0xD8, BUCKETS - 1)
        self.word(STATE + 0xE0, 0x51)
        self.word(STATE + 0xE8, case.outcome_items)
        self.word(STATE + 0x100, QUESTION_CTRL)
        self.word(STATE + 0x108, BUCKETS - 1)
        self.word(STATE + 0x110, 0x52)
        self.word(STATE + 0x118, case.question_items)
        self.install_table(case.outcomes, OUTCOME_LOW, OUTCOME_CTRL, OUTCOME_STRIDE, self.write_outcome)
        self.write_questions(case.questions)
        self.word(STATE + 0x180, TOKENS)
        self.word(STATE + 0x188, case.token_count)
        self.word(STATE + 0x168, SPOTS)
        self.word(STATE + 0x170, case.spot_count)
        for token in range(TOKEN_ROWS):
            row = TOKENS + token * TOKEN_STRIDE
            self.word(row + 0x58, TOKEN_WORDS + 8 * token)
            self.word(row + 0x60, case.spot_lens.get(token, 1))
            self.word(TOKEN_WORDS + 8 * token, case.spot(token))
        for spot in range(SPOT_ROWS):
            row = SPOTS + spot * SPOT_STRIDE
            self.word(row, 0x1000 + spot)
            self.word(row + 8, case.quote(spot))
        self.write_balances()
        self.word(AMOUNT, 0xFEED)

    def arguments(self, case):
        memory = self.machine.memory
        amount = 0 if case.amount is None else AMOUNT
        if case.kind == SPLIT:
            return {RDI: OUT, RSI: STATE, RDX: USER, RCX: case.outcome, R8: AMOUNT, R9: ORIGIN}
        if case.kind == MERGE:
            return {RDI: OUT, RSI: STATE, RDX: USER, RCX: case.outcome, R8: amount, R9: ORIGIN}
        if case.kind == MERGE_ALL:
            return {RDI: OUT, RSI: STATE, RDX: USER, RCX: case.question, R8: amount, R9: ORIGIN}
        if case.kind == NEGATE:
            memory.write(STACK_TOP - 0x100, 8, ORIGIN)
            return {RDI: OUT, RSI: STATE, RDX: USER, RCX: case.question, R8: case.outcome, R9: AMOUNT}
        if case.kind == SPLIT_LEGS:
            for slot, value in enumerate(case.input):
                self.word(INPUT + 8 * slot, value)
            return {RDI: OUT, RSI: STATE, RDX: INPUT}
        capacity, others, outcome, amount, token = case.input
        self.word(INPUT, capacity)
        self.word(INPUT + 8, VECTOR)
        self.word(INPUT + 0x10, len(others))
        self.word(INPUT + 0x18, outcome)
        self.word(INPUT + 0x20, amount)
        self.word(INPUT + 0x28, token)
        for slot, (other, tok) in enumerate(others):
            self.word(VECTOR + 16 * slot, other)
            self.word(VECTOR + 16 * slot + 8, tok)
        self.word(VECTOR + 16 * len(others), 0x7777)
        return {RDI: OUT, RSI: STATE, RDX: INPUT}

    def run(self, case):
        self.install(case)
        args = self.arguments(case)
        try:
            self.machine.run(case.kind, args)
        except Panicked as error:
            return ("panic", error.args[0], tuple(self.events))
        memory = self.machine.memory
        out = bytearray(memory.bytes_at(OUT, OUT_SIZE))
        if memory.read(OUT + OUT_SIZE, 1) != FILL:
            raise Halt("write past the output")
        rows = ()
        if case.kind == MERGE and self.read(OUT) == 0:
            out[8:16] = bytes(8)
        if case.kind in (MERGE_ALL, NEGATE) and self.read(OUT) != TAG_NONE:
            rows = tuple((self.read(VECTOR + 16 * index), self.read(VECTOR + 16 * index + 8)) for index in range(self.read(OUT + 0x10)))
        blocks = ()
        if case.kind in (SPLIT_LEGS, NEGATE_LEGS) and self.read(OUT + 8) == 2:
            debit = self.read(OUT + 0x78)
            credit = self.read(OUT + 0x90)
            count = self.read(OUT + 0x98)
            blocks = ((debit, tuple(self.read(debit + 8 * index) for index in range(3))),
                      (credit, tuple(self.read(credit + 8 * index) for index in range(3 * count))))
        return ("value", bytes(out), tuple(self.events), rows, blocks)


def residents(key, count):
    """Ids that start probing at the bucket of `key`, none sharing its seven hash bits."""
    home = hash_of(key)
    found = []
    other = 1000
    while len(found) < count:
        digest = hash_of(other)
        if digest & (BUCKETS - 1) == home & (BUCKETS - 1) and digest >> 57 != home >> 57:
            found.append(other)
        other += 1
    return found


def twin(key):
    """An id with the bucket and the seven hash bits of `key`."""
    home = hash_of(key)
    other = 1000
    while True:
        digest = hash_of(other)
        if digest & (BUCKETS - 1) == home & (BUCKETS - 1) and digest >> 57 == home >> 57:
            return other
        other += 1


def crowded(key=7, count=20, with_twin=True):
    entries = dict(Case().outcomes)
    for other in residents(key, count) + ([twin(key)] if with_twin else []):
        entries[other] = (21, 22, 1)
    return entries


def twinned(key=7):
    entries = dict(Case().outcomes)
    entries[twin(key)] = (21, 22, 1)
    return entries


def crowded_questions(key=3, count=21, with_twin=False):
    entries = dict(Case().questions)
    for other in residents(key, count) + ([twin(key)] if with_twin else []):
        entries[other] = (9, ())
    return entries


def twinned_questions(key=3):
    entries = dict(Case().questions)
    entries[twin(key)] = (9, ())
    return entries


def outcome_table_cases(kind, key, **fields):
    """Probe shapes for one outcome key; `key` is the id looked up first."""
    return (Case("first slot of the second group", kind, outcomes=crowded(key, 16, False), **fields),
            Case("first slot of the third group", kind, outcomes=crowded(key, 32, False), **fields),
            Case("hash twin in the same group", kind, outcomes=twinned(key), **fields),
            Case("hash twin three slots ahead", kind, outcomes=crowded(key, 2, True), **fields))


def question_table_cases(kind, **fields):
    return (Case("question at the first slot of the second group", kind, questions=crowded_questions(3, 16), **fields),
            Case("question at the first slot of the third group", kind, questions=crowded_questions(3, 32), **fields),
            Case("question with a hash twin in the same group", kind, questions=twinned_questions(3), **fields),
            Case("question hash twin three slots ahead", kind, questions=crowded_questions(3, 2, True), **fields),
            Case("unknown question with a resident twin", kind, question=33, questions=twinned_questions(33), **fields))


BIG = 1 << 40
HIGH = 1 << 63
LONG_SET = tuple(range(20, 34))
LONG_OUTCOMES = {key: (21, 22, 100) for key in LONG_SET}
LONG_OUTCOMES.update({7: (11, 12, 100), 8: (13, 14, 100), 9: (15, 16, 100)})
SPLIT_CASES = (
    Case("plain split", SPLIT),
    Case("amount equals the balance", SPLIT, amount=100000),
    Case("amount one unit above the balance", SPLIT, amount=100100),
    Case("amount 1 below a multiple", SPLIT, amount=999),
    Case("amount above 2^32, multiple", SPLIT, amount=1 << 40, outcomes={7: (11, 12, 1 << 8)}, balances={3: (1 << 41, 0)}),
    Case("amount above 2^32, remainder", SPLIT, amount=(1 << 40) + 1, outcomes={7: (11, 12, 1 << 8)}, balances={3: (1 << 41, 0)}),
    Case("unit above 2^32", SPLIT, amount=1 << 40, outcomes={7: (11, 12, 1 << 33)}, balances={3: (1 << 41, 0)}),
    Case("unit above 2^32 with remainder", SPLIT, amount=1 << 32, outcomes={7: (11, 12, 1 << 33)}, balances={3: (1 << 41, 0)}),
    Case("amount 0 passes the gate", SPLIT, amount=0),
    Case("unit 1", SPLIT, amount=7, outcomes={7: (11, 12, 1)}),
    Case("hold reduces the balance", SPLIT, balances={3: (1500, 500)}),
    Case("hold reduces below the amount", SPLIT, balances={3: (1500, 501)}),
    Case("hold above total: recorder, floor 0", SPLIT, amount=0, balances={3: (5, 6)}),
    Case("hold above total refuses a positive amount", SPLIT, balances={3: (5, 6)}),
    Case("no balances", SPLIT, balances={}),
    Case("balance key absent", SPLIT, balances={2: (1 << 20, 0), 4: (1 << 20, 0)}),
    Case("balance in a two-level tree, left", SPLIT, balances={1: (5, 0), 2: (6, 0), 3: (1000, 0), 4: (7, 0), 5: (8, 0), 6: (9, 0), 7: (10, 0)}, shape="two"),
    Case("balance at the root key", SPLIT, balances={1: (5, 0), 3: (1000, 0), 4: (7, 0)}, shape="two"),
    Case("balance key above every key", SPLIT, balances={0: (5, 0), 1: (1000, 0), 2: (7, 0)}, shape="two", amount=0),
    Case("balance key below every key", SPLIT, balances={4: (5, 0), 5: (1000, 0), 6: (7, 0)}, shape="two"),
    Case("balance key inside a child, absent", SPLIT, balances={1: (5, 0), 2: (6, 0), 4: (7, 0), 5: (8, 0)}, shape="two"),
    Case("empty outcome table", SPLIT, outcome_items=0),
    Case("unknown outcome", SPLIT, outcome=77),
    Case("registry miss word", SPLIT, registry=8),
    Case("registry hit: status 6", SPLIT, registry=7),
    Case("outcome past a full probe group, with a hash twin", SPLIT, outcomes=crowded()),
    Case("unknown outcome over a crowded table", SPLIT, outcome=77, outcomes=crowded()),
    Case("side A with two spots: status 8", SPLIT, spot_lens={11: 2}),
    Case("side B with no spots: status 8", SPLIT, spot_lens={12: 0}),
    Case("sides on different quote tokens: status 8", SPLIT, quotes={12: 4}),
    Case("side A token past the table", SPLIT, outcomes={7: (40, 12, 100)}),
    Case("side B token past the table", SPLIT, outcomes={7: (11, 40, 100)}),
    Case("side B token past a short table", SPLIT, token_count=12),
    Case("side A spot past the table", SPLIT, token_of={11: 40}),
    Case("side B spot past the table", SPLIT, token_of={12: 40}),
    Case("side B spot past a short table", SPLIT, spot_count=12),
    Case("quote word other than 3", SPLIT, quotes={11: 5, 12: 5}, balances={3: (1, 0), 5: (5000, 0)}),
    Case("amount refused by the converter: status 1", SPLIT, amount="bad"),
    Case("amount just above 2^32, multiple", SPLIT, amount=4294967300, balances={3: (1 << 34, 0)}),
    Case("unknown outcome with a resident twin", SPLIT, outcome=77, outcomes=twinned(77)),
) + outcome_table_cases(SPLIT, 7)
MERGE_CASES = (
    Case("plain merge", MERGE),
    Case("no amount", MERGE, amount=None),
    Case("exact least side", MERGE, amount=5000),
    Case("one piece above the least side", MERGE, amount=5100),
    Case("side B is the smaller", MERGE, amount=4000, balances={3: (1, 0), 11: (90, 0), 12: (40, 0)}),
    Case("side B one short", MERGE, amount=4100, balances={3: (1, 0), 11: (90, 0), 12: (40, 0)}),
    Case("side A one short", MERGE, amount=4100, balances={3: (1, 0), 11: (40, 0), 12: (90, 0)}),
    Case("remainder: status 1", MERGE, amount=150),
    Case("amount refused: status 1", MERGE, amount="bad"),
    Case("amount 0", MERGE, amount=0),
    Case("amount above 2^32, multiple", MERGE, amount=1 << 40, outcomes={7: (11, 12, 1 << 20)}, balances={11: (1 << 20, 0), 12: (1 << 21, 0)}),
    Case("amount above 2^32, remainder", MERGE, amount=(1 << 40) + 1, outcomes={7: (11, 12, 1 << 20)}, balances={11: (1 << 20, 0), 12: (1 << 21, 0)}),
    Case("unit above 2^32", MERGE, amount=3 << 33, outcomes={7: (11, 12, 1 << 33)}, balances={11: (3, 0), 12: (3, 0)}),
    Case("unit above 2^32, one short", MERGE, amount=3 << 33, outcomes={7: (11, 12, 1 << 33)}, balances={11: (2, 0), 12: (3, 0)}),
    Case("hold on side A", MERGE, amount=4000, balances={11: (50, 10), 12: (70, 0)}),
    Case("hold above total on side A", MERGE, amount=0, balances={11: (5, 10), 12: (70, 0)}),
    Case("hold above total on side B", MERGE, amount=100, balances={11: (70, 0), 12: (5, 10)}),
    Case("hold on side B", MERGE, amount=2000, balances={11: (70, 0), 12: (22, 2)}),
    Case("no balances", MERGE, balances={}, amount=0),
    Case("no balances, positive amount", MERGE, balances={}),
    Case("balances in two levels", MERGE, balances={1: (5, 0), 9: (6, 0), 11: (20, 0), 12: (30, 0), 13: (7, 0), 14: (8, 0), 15: (9, 0)}, shape="two", amount=2000),
    Case("side B at the root", MERGE, balances={1: (5, 0), 12: (60, 0), 13: (7, 0), 11: (70, 0)}, shape="two", amount=6000),
    Case("side A absent in a tree", MERGE, balances={1: (5, 0), 12: (60, 0), 13: (7, 0)}, shape="two", amount=100),
    Case("side B absent in a tree", MERGE, balances={1: (5, 0), 11: (60, 0), 13: (7, 0)}, shape="two", amount=100),
    Case("side keys above every key", MERGE, balances={1: (5, 0), 2: (60, 0), 3: (7, 0)}, shape="two", amount=0),
    Case("empty outcome table: status 8", MERGE, outcome_items=0),
    Case("unknown outcome: status 8", MERGE, outcome=77),
    Case("two spots on side A: status 8", MERGE, spot_lens={11: 2}),
    Case("two spots on side B: status 8", MERGE, spot_lens={12: 2}),
    Case("different quote tokens: status 8", MERGE, quotes={12: 4}),
    Case("outcome past a full probe group", MERGE, outcomes=crowded()),
    Case("unknown over a crowded table", MERGE, outcome=77, outcomes=crowded()),
    Case("side token past the table", MERGE, outcomes={7: (11, 40, 100)}),
    Case("amount just above 2^32, multiple", MERGE, amount=4294967300, balances={11: (1 << 34, 0), 12: (1 << 34, 0)}),
    Case("unknown outcome with a resident twin", MERGE, outcome=77, outcomes=twinned(77)),
    Case("unit 0 reads as the failure niche: status 8", MERGE, outcomes={7: (11, 12, 0)}),
    Case("unit 0 with no amount: status 8", MERGE, amount=None, outcomes={7: (11, 12, 0)}),
) + outcome_table_cases(MERGE, 7)
MERGE_ALL_CASES = (
    Case("plain merge question, no amount", MERGE_ALL, amount=None),
    Case("amount equals the least", MERGE_ALL, amount=40, balances={11: (50, 0), 13: (40, 0), 15: (41, 0)}),
    Case("amount above the least", MERGE_ALL, amount=41, balances={11: (50, 0), 13: (40, 0), 15: (41, 0)}),
    Case("fallback holds the least", MERGE_ALL, amount=None, balances={11: (2, 0), 13: (40, 0), 15: (41, 0)}),
    Case("first named holds the least", MERGE_ALL, amount=None, balances={11: (50, 0), 13: (3, 0), 15: (41, 0)}),
    Case("last named holds the least", MERGE_ALL, amount=None, balances={11: (50, 0), 13: (40, 0), 15: (1, 0)}),
    Case("one named absent: least 0", MERGE_ALL, amount=None, balances={11: (50, 0), 15: (41, 0)}),
    Case("amount refused: status 1", MERGE_ALL, amount="bad"),
    Case("hold counts", MERGE_ALL, amount=None, balances={11: (50, 9), 13: (40, 0), 15: (41, 0)}),
    Case("hold above total: recorder", MERGE_ALL, amount=None, balances={11: (50, 51), 13: (40, 0), 15: (41, 0)}),
    Case("empty question table", MERGE_ALL, question_items=0),
    Case("unknown question", MERGE_ALL, question=33),
    Case("empty outcome table", MERGE_ALL, outcome_items=0),
    Case("fallback has no record", MERGE_ALL, questions={3: (70, (8, 9))}),
    Case("named outcome has no record: vector freed", MERGE_ALL, questions={3: (7, (8, 70))}),
    Case("no named outcomes", MERGE_ALL, amount=None, questions={3: (7, ())}),
    Case("no named outcomes, amount", MERGE_ALL, amount=50, questions={3: (7, ())}),
    Case("four members: no second growth", MERGE_ALL, amount=None, questions={3: (7, (8, 9, 20))}, outcomes=LONG_OUTCOMES),
    Case("five members: second growth", MERGE_ALL, amount=None, questions={3: (7, (8, 9, 20, 21))}, outcomes=LONG_OUTCOMES),
    Case("named set of twelve: two levels", MERGE_ALL, amount=None, questions={3: (7, LONG_SET[:12])}, outcomes=LONG_OUTCOMES, set_shape="two"),
    Case("named set of three: root then right", MERGE_ALL, amount=None, questions={3: (7, (8, 9, 20))}, outcomes=LONG_OUTCOMES, set_shape="two"),
    Case("balances in two levels", MERGE_ALL, amount=None, balances={1: (5, 0), 11: (50, 0), 13: (40, 0), 14: (9, 0), 15: (41, 0), 16: (7, 0), 17: (9, 0)}, shape="two"),
    Case("balance above every key", MERGE_ALL, amount=None, balances={1: (5, 0), 2: (5, 0), 3: (5, 0)}, shape="two"),
    Case("question past a full probe group", MERGE_ALL, amount=None, questions=crowded_questions()),
    Case("unknown over a crowded table", MERGE_ALL, amount=None, question=33, questions=crowded_questions()),
    Case("outcome past a full probe group", MERGE_ALL, amount=None, outcomes=crowded()),
    Case("no balances", MERGE_ALL, amount=None, balances={}),
    Case("converted on the fallback token, not the quote", MERGE_ALL, amount=30, quotes={11: 6, 12: 6}),
    Case("member with no record, resident twin", MERGE_ALL, amount=None, questions={3: (7, (8, 77))}, outcomes=twinned(77)),
) + outcome_table_cases(MERGE_ALL, 7, amount=None) + question_table_cases(MERGE_ALL, amount=None)
NEGATE_CASES = (
    Case("plain negate", NEGATE, outcome=8, amount=70),
    Case("amount equals the balance", NEGATE, outcome=8, amount=80),
    Case("amount above the balance", NEGATE, outcome=8, amount=81),
    Case("second named", NEGATE, outcome=9, amount=40),
    Case("fallback named: status 5", NEGATE, outcome=7),
    Case("not a member: status 4", NEGATE, outcome=70),
    Case("member with no record: status 8", NEGATE, outcome=70, questions={3: (7, (8, 70))}),
    Case("other member with no record: vector freed", NEGATE, outcome=8, amount=1, questions={3: (7, (8, 70))}),
    Case("fallback with no record: nothing to free", NEGATE, outcome=8, amount=1, questions={3: (70, (8, 9))}),
    Case("amount refused: status 1", NEGATE, outcome=8, amount="bad"),
    Case("amount 0", NEGATE, outcome=8, amount=0),
    Case("no balance entry", NEGATE, outcome=8, amount=0, balances={3: (1, 0)}),
    Case("no balance entry, positive", NEGATE, outcome=8, amount=1, balances={3: (1, 0)}),
    Case("no balances at all", NEGATE, outcome=8, amount=1, balances={}),
    Case("hold counts", NEGATE, outcome=8, amount=70, balances={14: (80, 10)}),
    Case("hold counts, one over", NEGATE, outcome=8, amount=71, balances={14: (80, 10)}),
    Case("hold above total: recorder", NEGATE, outcome=8, amount=0, balances={14: (5, 6)}),
    Case("balances two levels", NEGATE, outcome=8, amount=5, balances={1: (1, 0), 13: (1, 0), 14: (6, 0), 15: (1, 0), 16: (1, 0)}, shape="two"),
    Case("balance key above every key", NEGATE, outcome=8, amount=0, balances={1: (1, 0), 2: (1, 0), 3: (1, 0)}, shape="two"),
    Case("balance key between keys", NEGATE, outcome=8, amount=0, balances={1: (1, 0), 13: (1, 0), 15: (1, 0)}, shape="two"),
    Case("empty question table", NEGATE, question_items=0),
    Case("unknown question", NEGATE, question=33),
    Case("empty outcome table", NEGATE, outcome=8, outcome_items=0),
    Case("no named outcomes: status 4", NEGATE, outcome=8, questions={3: (7, ())}),
    Case("one named: fallback only row", NEGATE, outcome=8, amount=1, questions={3: (7, (8,))}),
    Case("six members: growth", NEGATE, outcome=8, amount=1, questions={3: (7, (8, 9, 20, 21, 22, 23))}, outcomes=LONG_OUTCOMES),
    Case("three named two levels, root member", NEGATE, outcome=9, amount=1, questions={3: (7, (8, 9, 20))}, outcomes=LONG_OUTCOMES, set_shape="two"),
    Case("twelve named two levels, right member", NEGATE, outcome=30, amount=1, questions={3: (7, LONG_SET[:12])}, outcomes=LONG_OUTCOMES, set_shape="two"),
    Case("twelve named two levels, left member", NEGATE, outcome=21, amount=1, questions={3: (7, LONG_SET[:12])}, outcomes=LONG_OUTCOMES, set_shape="two"),
    Case("twelve named, last member", NEGATE, outcome=31, amount=1, questions={3: (7, LONG_SET[:12])}, outcomes=LONG_OUTCOMES, set_shape="two"),
    Case("question past a full probe group", NEGATE, outcome=8, amount=1, questions=crowded_questions()),
    Case("unknown over a crowded table", NEGATE, question=33, questions=crowded_questions()),
    Case("outcome past a full probe group", NEGATE, outcome=8, amount=1, outcomes=crowded()),
    Case("member outcome past a full group, sibling first", NEGATE, outcome=7, amount=1, questions={3: (8, (7, 9))}, outcomes=crowded()),
    Case("other member over a crowded table with no record", NEGATE, outcome=7, amount=1, questions={3: (8, (7, 77))}, outcomes=crowded()),
    Case("own outcome over a crowded table with no record", NEGATE, outcome=77, amount=1, questions={3: (8, (77,))}, outcomes=crowded()),
    Case("own record missing, resident twin", NEGATE, outcome=77, amount=1, questions={3: (7, (77, 9))}, outcomes=twinned(77)),
    Case("other record missing, resident twin", NEGATE, outcome=8, amount=1, questions={3: (7, (8, 77))}, outcomes=twinned(77)),
) + outcome_table_cases(NEGATE, 8, outcome=8, amount=1) + outcome_table_cases(NEGATE, 7, outcome=8, amount=1) + question_table_cases(NEGATE, outcome=8, amount=1)
SPLIT_LEG_CASES = (
    Case("plain legs", SPLIT_LEGS, input=(7, 3, 1000)),
    Case("unit equals the amount", SPLIT_LEGS, input=(7, 3, 100)),
    Case("amount below the unit: 3", SPLIT_LEGS, input=(7, 3, 99)),
    Case("amount 0: 3", SPLIT_LEGS, input=(7, 3, 0)),
    Case("no exact-multiple check here", SPLIT_LEGS, input=(7, 3, 1050)),
    Case("amount above 2^32", SPLIT_LEGS, input=(7, 3, 1 << 40)),
    Case("unit above 2^32", SPLIT_LEGS, input=(7, 3, 3 << 33), outcomes={7: (11, 12, 1 << 33)}),
    Case("unit above 2^32 and above the amount", SPLIT_LEGS, input=(7, 3, 1 << 32), outcomes={7: (11, 12, 1 << 33)}),
    Case("empty table", SPLIT_LEGS, input=(7, 3, 1000), outcome_items=0),
    Case("unknown outcome", SPLIT_LEGS, input=(77, 3, 1000)),
    Case("outcome past a full probe group", SPLIT_LEGS, input=(7, 3, 1000), outcomes=crowded()),
    Case("unknown over a crowded table", SPLIT_LEGS, input=(77, 3, 1000), outcomes=crowded()),
    Case("side tokens carried", SPLIT_LEGS, input=(8, 9, 300)),
    Case("amount just above 2^32", SPLIT_LEGS, input=(7, 3, 4294967300)),
    Case("unknown outcome with a resident twin", SPLIT_LEGS, input=(77, 3, 1000), outcomes=twinned(77)),
) + outcome_table_cases(SPLIT_LEGS, 7, input=(7, 3, 1000))
NEGATE_LEG_CASES = (
    Case("two rows", NEGATE_LEGS, input=(4, ((7, 11), (9, 15)), 8, 70, 14)),
    Case("amount 0: 3, input freed", NEGATE_LEGS, input=(4, ((7, 11),), 8, 0, 14)),
    Case("amount 0, no input capacity", NEGATE_LEGS, input=(0, (), 8, 0, 14)),
    Case("no input capacity, no rows", NEGATE_LEGS, input=(0, (), 8, 5, 14)),
    Case("capacity but no rows", NEGATE_LEGS, input=(4, (), 8, 5, 14)),
    Case("five rows: second growth", NEGATE_LEGS, input=(8, ((1, 2), (3, 4), (5, 6), (7, 8), (9, 10)), 8, 5, 14)),
    Case("large amount", NEGATE_LEGS, input=(4, ((7, 11),), 8, MAX_U64, 14)),
)
CASE_LISTS = {SPLIT: SPLIT_CASES, MERGE: MERGE_CASES, MERGE_ALL: MERGE_ALL_CASES, NEGATE: NEGATE_CASES, SPLIT_LEGS: SPLIT_LEG_CASES, NEGATE_LEGS: NEGATE_LEG_CASES}
ALL_CASES = tuple(case for kind in (SPLIT, MERGE, MERGE_ALL, NEGATE, SPLIT_LEGS, NEGATE_LEGS) for case in CASE_LISTS[kind])


def lcg(seed):
    state = seed & MASK[8]
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield state


def vector_cases(count):
    random = lcg(0x37250D0)
    cases = []
    edge = (0, 1, 2, 99, 100, 101, 999, 1000, 1 << 31, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, HIGH - 1, HIGH, MAX_U64 - 1, MAX_U64)
    units = (1, 2, 3, 10, 100, 1000, 100000, 1 << 16, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, 1 << 40, HIGH, MAX_U64)
    kinds = (SPLIT, MERGE, MERGE_ALL, NEGATE)
    for index in range(count):
        kind = kinds[index % 4]
        def value():
            pick = next(random)
            return edge[next(random) % len(edge)] if pick & 1 else next(random) >> (next(random) % 64)
        unit = units[next(random) % len(units)]
        amount = value() if next(random) % 3 else unit * (next(random) >> (next(random) % 64 | 1)) & MAX_U64
        if next(random) % 9 == 0:
            amount = "bad"
        elif kind in (MERGE, MERGE_ALL) and next(random) % 5 == 0:
            amount = None
        balances = {}
        for key in (3, 11, 12, 13, 14, 15, 16):
            if next(random) % 8:
                balances[key] = (value(), value() if next(random) % 4 == 0 else 0)
        outcomes = {7: (11, 12, unit), 8: (13, 14, unit), 9: (15, 16, unit)}
        cases.append(Case("", kind, amount=amount, balances=balances, outcomes=outcomes, outcome=7 + next(random) % 3, registry=7 if next(random) % 7 == 0 else None,
                          shape=("leaf", "two")[next(random) & 1]))
    return cases


def check_cases(harness, cases):
    rows = []
    for case in cases:
        got = harness.run(case)
        want = spec_run(case)
        if got != want:
            raise EvidenceError("mismatch for %s (%#x): %r != %r" % (case.name or (case.amount, case.outcomes, case.balances), case.kind, got, want))
        rows.append(got)
    return rows


def slot_rows(image, relative):
    rows = []
    names = {SLOT_REGISTRY: "registry lookup", SLOT_CONVERT: "amount converter", SLOT_HOLDER: "balance map of a user", SLOT_RECORD: "recorder", SLOT_GROW16: "vector growth, 16-byte rows",
             SLOT_GROW24: "vector growth, 24-byte rows", SLOT_ALLOC: "allocator", SLOT_FREE: "free", SLOT_ALLOC_FAIL: "allocation failure", SLOT_PANIC_RDI: "panic", SLOT_PANIC_RDX: "bounds panic"}
    for slot, name in sorted(names.items()):
        rows.append(("%#x" % slot, name, "%#x" % relative[slot] if slot in relative else "filled by the loader"))
    for target, slot in sorted(SLOTS.items()):
        if relative.get(slot) != target:
            raise EvidenceError("slot %#x does not name %#x" % (slot, target))
        rows.append(("%#x" % slot, NAMES[target], "%#x" % target))
    return rows


def call_site_rows(image):
    low, data = image.text_bytes()
    wanted = {slot: target for target, slot in SLOTS.items()}
    found = {target: [] for target in SLOTS}
    at = data.find(b"\xFF\x15")
    while at >= 0:
        if at + 6 <= len(data):
            slot = low + at + 6 + struct.unpack_from("<i", data, at + 2)[0]
            if slot in wanted:
                found[wanted[slot]].append(low + at)
        at = data.find(b"\xFF\x15", at + 1)
    direct = {}
    at = data.find(b"\xE8")
    while at >= 0:
        if at + 5 <= len(data):
            target = low + at + 5 + struct.unpack_from("<i", data, at + 1)[0]
            if target in found:
                direct.setdefault(target, []).append(low + at)
        at = data.find(b"\xE8", at + 1)
    rows = []
    for target in sorted(found):
        if direct.get(target):
            raise EvidenceError("direct call to %#x" % target)
        rows.append(("%#x" % target, NAMES[target], len(found[target]), ",".join("%#x" % va for va in found[target])))
    return rows


def location_rows(image, relative):
    return [("%#x" % va,) + tuple(image.location(va, relative)) for va in (LOC_TOKEN_TABLE, LOC_SPOT_TABLE, LOC_WEI_SUB)]


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
            if harness.run(case) != spec_run(case):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError):
            return case
    return None


PSHUFD = "pshufd selector 0x45 instead of 0x44: every byte of the source lane is the same tag, so the pattern does not change"
HEIGHT_8 = "the eight-step shortcut of the B-tree descent; the fixtures have height at most 1"
HEIGHT_2 = "the child step of a descent of height 2 or more; the fixtures have height at most 1"
NON_EMPTY = "the leaf length after a descent is read only to test for an empty leaf, which a non-empty tree does not hold"
STALE_SIDE = "a refused side leaves a stale word; with the test gone the equality compare after it still ends in status 8"
IGNORED = "the merge gate reads only the unit word on this path and writes status 8 itself, so the status byte of the helper is never read"
DANGLING = "the empty vector pointer is replaced by growth before any read, because the first member always pushes"
EXPECTED_SURVIVORS = {
    (0x3725166, "immediate"): PSHUFD, (0x3725431, "immediate"): PSHUFD, (0x3725754, "immediate"): PSHUFD, (0x3725B1B, "immediate"): PSHUFD,
    (0x3725DA0, "immediate"): PSHUFD, (0x3726196, "immediate"): PSHUFD, (0x37267BE, "immediate"): PSHUFD, (0x385C1B3, "immediate"): PSHUFD,
    (0x3725622, "immediate"): HEIGHT_8, (0x3725C42, "immediate"): HEIGHT_8, (0x372605D, "immediate"): HEIGHT_8,
    (0x37256D5, "immediate"): HEIGHT_8, (0x3725CF5, "immediate"): HEIGHT_8, (0x3726106, "immediate"): HEIGHT_8,
    (0x37256C3, "displacement"): HEIGHT_2, (0x3725CE3, "displacement"): HEIGHT_2, (0x37260F3, "displacement"): HEIGHT_2,
    (0x372566C, "displacement"): NON_EMPTY, (0x3725C8A, "displacement"): NON_EMPTY, (0x372609C, "displacement"): NON_EMPTY,
    (0x37251F7, "immediate"): STALE_SIDE, (0x37251FE, "immediate"): STALE_SIDE, (0x385C248, "immediate"): STALE_SIDE, (0x385C256, "immediate"): STALE_SIDE,
    (0x385C229, "immediate"): IGNORED, (0x385C229, "displacement"): IGNORED, (0x385C265, "displacement"): IGNORED, (0x385C286, "immediate"): IGNORED,
    (0x37254DE, "immediate"): DANGLING, (0x3725F77, "immediate"): DANGLING,
    (0x3725564, "immediate"): "the first pass reads an unset stack word as the running least only under this edit; the fixture stack word is larger than every balance",
    (0x3725F80, "immediate"): "the vector length word at this slot is rewritten by every push and the first member always pushes",
    (0x3725FE7, "immediate"): "al is 0 on every path to this test, so the mask does not change it",
    (0x3726285, "immediate"): "al is 0 on every path to this test, so the mask does not change it",
}


def run_mutants(image, rows, seen):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, ALL_CASES) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    spans = [(image.exact_fde(target), target) for target in TARGETS]
    for va, kind, patch in edits_for(image, rows, seen):
        target = next(target for (low, high), target in spans if low <= va < high)
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        if first_failure(harness, CASE_LISTS[MERGE if target == PAIR_HELPER else target]) is not None:
            results.append((va, kind, "killed", "whole run"))
        else:
            results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results


STRINGS = (b"struct variant UserOutcomeAction::SplitOutcome with 2 elements", b"struct variant UserOutcomeAction::MergeOutcome with 2 elements",
           b"struct variant UserOutcomeAction::MergeQuestion with 2 elements", b"struct variant UserOutcomeAction::NegateOutcome with 3 elements",
           b"splitOutcomemergeOutcomemergeQuestionnegateOutcome", b"fallbackOutcome", b"namedOutcomes", b"settledNamedOutcomes")


def string_rows(image):
    rows = []
    for text in STRINGS:
        at = image.blob.find(text)
        if at < 0:
            raise EvidenceError("string missing: %r" % text)
        rows.append(("%#x" % at, text.decode("ascii"), image.blob.count(text)))
    return rows


STATUS_TABLE = 0x59B088
STATUS_ARMS = 10
ARM_HEAD = bytes.fromhex("488b3e488b4608488b4018488d35")


def status_rows(image):
    """Status byte to text: each arm of the Display at 0x3815010 is lea text; mov len; jmp."""
    rows = []
    base = image.offset(STATUS_TABLE)
    for index in range(STATUS_ARMS):
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, base + 4 * index)[0]
        at = image.offset(arm)
        data = bytes(image.blob[at:at + 26])
        if data[:14] != ARM_HEAD or data[18] != 0xBA or data[23:25] != b"\xFF\xE0":
            raise EvidenceError("status arm %d has another shape" % index)
        text = arm + 18 + struct.unpack_from("<i", data, 14)[0]
        size = struct.unpack_from("<I", data, 19)[0]
        rows.append((index, "%#x" % arm, "%#x" % text, bytes(image.blob[image.offset(text):image.offset(text) + size]).decode("ascii")))
    return rows


def division_rows(rows):
    """Every div row, with the rows that test its divisor between the table read and the div."""
    return [("%#x" % row.va, row.data.hex(), row.width) for row in rows if row.op == "div"]


def analyse(image, mutate=True, vectors=400):
    relative = image.relative()
    harness = Harness(image)
    outcomes = check_cases(harness, ALL_CASES)
    check_cases(harness, vector_cases(vectors))
    seen = set(harness.machine.seen)
    fde = {target: image.exact_fde(target) for target in TARGETS}
    table = {target: decode_range(image, *fde[target]) for target in TARGETS}
    rows = [row for target in TARGETS for row in table[target]]
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(fde=fde, table=table, rows=rows, named=ALL_CASES, outcomes=outcomes, vector_count=vectors, unreached=unreached,
                  slots=slot_rows(image, relative), sites=call_site_rows(image), locations=location_rows(image, relative), divisions=division_rows(rows), strings=string_rows(image), statuses=status_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, rows, seen)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    if outcome[0] == "panic":
        return ("panic", "%#x" % outcome[1], "", ",".join(event[0] for event in outcome[2]), "")
    _, out, events, rows, blocks = outcome
    words = ",".join("%#x" % word for word in struct.unpack_from("<6Q", out.ljust(0x30, bytes([FILL]))))
    return ("value", words, ",".join("%s:%#x" % (row[0], row[1]) for row in rows), ",".join(event[0] for event in events),
            ";".join(",".join("%#x" % cell for cell in block[1]) for block in blocks))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("slots.tsv", ("slot", "role", "relative_target"), result["slots"])
    tsv("call-sites.tsv", ("function", "name", "sites", "addresses"), result["sites"])
    tsv("locations.tsv", ("record", "path", "line", "column"), result["locations"])
    tsv("divisions.tsv", ("address", "bytes", "width"), result["divisions"])
    tsv("strings.tsv", ("file_offset", "text", "count"), result["strings"])
    tsv("status-text.tsv", ("status", "arm", "text_address", "text"), result["statuses"])
    tsv("outcomes.tsv", ("function", "case", "end", "first_six_output_words", "vector", "events", "leg_blocks"),
        [("%#x" % case.kind, case.name) + describe(case, outcome) for case, outcome in zip(result["named"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"fde": ["%#x" % value for value in result["fde"][target]], "bytes": result["fde"][target][1] - result["fde"][target][0],
                                      "instructions": len(result["table"][target]), "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["named"]), "vector_cases": result["vector_count"],
    }
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[2] == "killed"),
                                "survived": sum(1 for r in rows if r[2] == "survived")}
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
