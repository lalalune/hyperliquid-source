#!/usr/bin/env python3
"""Run node #94 commit walk 0x44ab970 from bytes and map when a block commits and what the commit does.

The real rows of the walk and nine helpers run under named stubs with real B-tree fixtures, a separate rule list
predicts every outcome and every state write, and every reached conditional row and immediate is mutated. Call
sites, pins and constants come from fixed bytes. No objdump or readelf output is parsed and the binary is never
executed. Standard library only.

    python3 tools/commit_walk_path.py --out <dir>
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
HEAP_SIZE = 0x30000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 1500000
MUTANT_STEP_LIMIT = 100000


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
        for marker in ("/node/", "/library/"):
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
        if two == 0xA5:
            reg, rm = modrm()
            return finish("shldc", rm, ("r", reg), width)
        if two == 0xAC:
            reg, rm = modrm()
            value = immediate(1) & 0xFF
            return finish("shrdi", rm, ("r", reg), width, target=value)
        if two == 0xAD:
            reg, rm = modrm()
            return finish("shrd", rm, ("r", reg), width)
        if two in (0xB0, 0xB1):
            reg, rm = modrm()
            return finish("cmpxchg", rm, ("r", reg), 1 if two == 0xB0 else width)
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
            source = self.get(row.b, width)
            product = (source - (1 << (8 * width)) if source & SIGN[width] else source) * row.target
            self.put(row.a, width, product)
            self.of = self.cf = not -SIGN[width] <= product < SIGN[width]
        elif op == "imul1":
            left, right = self.regs[RAX], self.get(row.a, 8)
            product = (left - (1 << 64) if left & SIGN[8] else left) * (right - (1 << 64) if right & SIGN[8] else right)
            self.regs[RAX] = product & MASK[8]
            self.regs[RDX] = (product >> 64) & MASK[8]
        elif op == "cmpxchg":
            current = self.get(row.a, width)
            self.add_sub(self.regs[RAX] & MASK[width], current, 0, width, True)
            if self.zf:
                self.put(row.a, width, self.get(row.b, width))
            else:
                self.put(("r", RAX), width, current)
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
        elif op == "shldc":
            bits = 8 * width
            count = self.regs[RCX] & (bits - 1)
            high, low = self.get(row.a, width), self.get(row.b, width)
            self.put(row.a, width, (high << count | low >> (bits - count)) if count else high)
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


MARK_BASE = 0x7700000000
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_ALLOC = 0x576DFD8
SLOT_DEALLOC = 0x576E010
SLOT_GROW_HASHES = 0x5775090
SLOT_GROW_BLOCK_HASHES = 0x57769D8
SLOT_GROW_COMMITTED = 0x5775098
SLOT_GROW_OUT = 0x57769D0
SLOT_GROW_DROPPED = 0x5776A58
SLOT_GROW_DEQUE = 0x5776648
SLOT_BTREE_PANIC = 0x576E470
SLOT_WALL = 0x576E8A0
SLOT_TIME_ADD = 0x576E8A8
SLOT_DATE_ADD = 0x576E8B0
SLOT_LAZY = 0x576F488
SLOT_ADD_SECS = 0x576EFB8
SLOT_SIGNED = 0x576EAA0
SLOT_FORMAT = 0x576E040
SLOT_LOCK_WAIT = 0x576EF30
SLOT_LOCK_WAKE = 0x576EF38
SLOT_TIME_SUB = 0x576E8C0
ONCE_WORD = 0x577AB98
COMMIT = 0x44AB970
COLLECT = 0x47C05F0
TX_PRUNE = 0x489B640
BLOCK_PRUNE = 0x48980C0
TX_REMOVE = 0x4942500
ASK = 0x44B8050
SEEN_INSERT = 0x4356A60
KIND_SET = 0x492D4B0
EXTEND = 0x47F51E0
TIME_SUB = 0x1447130
STATIC_FUNCTIONS = (COMMIT, COLLECT, TX_PRUNE, BLOCK_PRUNE, TX_REMOVE, ASK, SEEN_INSERT, KIND_SET, EXTEND, TIME_SUB)
ROLES = {COMMIT: "commit rule, ancestor walk, tx removal, stats, event push", COLLECT: "tx hashes of one block to shared tx records", TX_PRUNE: "next tx older than 20 s past event time",
         BLOCK_PRUNE: "next block below the committed round", TX_REMOVE: "tx map remove by key", ASK: "one-shot request throttle", SEEN_INSERT: "bounded seen tx map plus deque",
         KIND_SET: "reason byte set of one throttle row", EXTEND: "commit records to tag 3 outbox rows", TIME_SUB: "difference of two times in f64 seconds, truncated to microseconds"}
STUBS = {0x454C050: "block digest, returns the map key of the block it was given", 0x44C52B0: "block clone, byte copy of 0xb0", 0x4847500: "signature vector clone, byte copy of 24",
         0x4851A70: "drop of the partial commit records", 0x470AD70: "log 'committed', checks labels and records both lists", 0x470B4C0: "log 'dropping txs'", 0x470B860: "log 'dropping blocks'",
         0x470CBC0: "log 'Making request after wait duration'", 0x4A112A0: "stat counter record", 0x4A11410: "stat sample record", 0x42B27E0: "tx map remove at a leaf handle", 0x42B2030: "tx map remove at a leaf handle",
         0x42B43B0: "block map remove at a leaf handle", 0x4480730: "drop of a removed tx", 0x447E5C0: "drop of a removed block", 0x44C6E70: "drop of the record iterator", 0x42B91F0: "throttle map search",
         0x4958740: "throttle entry, inserts a row stamped with event time, stat 4 and a log", 0x4235420: "reason byte leaf insert", 0x495A2E0: "seen map insert", 0x49460D0: "seen map remove", 0x454F5D0: "vector reserve, doubles"}
SLOT_STUBS = {SLOT_MEMCMP: "memcmp", SLOT_MEMCPY: "memcpy", SLOT_ALLOC: "fixture bump allocator", SLOT_DEALLOC: "dealloc, no effect", SLOT_GROW_HASHES: "32 byte vector growth", SLOT_GROW_BLOCK_HASHES: "32 byte vector growth",
              SLOT_GROW_COMMITTED: "32 byte vector growth", SLOT_GROW_OUT: "outbox growth, 0x168 byte rows", SLOT_GROW_DROPPED: "0x2c byte vector growth", SLOT_GROW_DEQUE: "deque growth, halts", SLOT_BTREE_PANIC: "unwrap on an empty tree",
              SLOT_WALL: "wall clock, case value plus one second per call", SLOT_TIME_ADD: "chrono time plus TimeDelta, rule read from its use", SLOT_DATE_ADD: "chrono date plus days, packed ordinal only", SLOT_LAZY: "lazy global getter 0x14385c0, recorded",
              SLOT_ADD_SECS: "time plus f64 seconds", SLOT_SIGNED: "chrono signed difference", SLOT_FORMAT: "format of the Time Sub warning", SLOT_LOCK_WAIT: "contended lock, halts", SLOT_LOCK_WAKE: "contended unlock, halts"}
NONE_TAG = 1 << 63
TX_SKIP_TAG = (1 << 63) + 1
TX_NONE_TAG = (1 << 63) + 2
I64_MAX = (1 << 63) - 1
U64_MAX = (1 << 64) - 1
DATE = (2025 << 13) | (200 << 4) | 0xE
STATE = HEAP_BASE + 0x1000
STATE_SIZE = 0xB08
OUTBOX = HEAP_BASE + 0x2000
OUTBOX_CAP = 16
RECORD = 0x168
OBJECTS = HEAP_BASE + 0x6000
OBJ_ASK, OBJ_LOG, OBJ_STAT, OBJ_LAT = (OBJECTS + 0x40 * index for index in range(4))
DEQUE = HEAP_BASE + 0x6400
DEQUE_CAP = 64
SIZES = HEAP_BASE + 0x7000
NODES = HEAP_BASE + 0xA000
THROTTLE_ROOT = HEAP_BASE + 0x6100
USED = HEAP_SIZE
TX_VALUE = 0x58
BLOCK_VALUE = 0xF8
TX_KEEP_SECONDS = 20
ASK_WAIT = 1.0
BLOCK_TIME_DAY = 39000
STATE_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(STATE_SIZE))


class Layout:
    def __init__(self, key_at, key_size, val_at, val_size, parent_at, pidx_at, len_at, edges_at):
        self.key_at, self.key_size, self.val_at, self.val_size = key_at, key_size, val_at, val_size
        self.parent_at, self.pidx_at, self.len_at, self.edges_at = parent_at, pidx_at, len_at, edges_at
        self.size = edges_at + 12 * 8


TX_LAYOUT = Layout(0, 32, 0x168, TX_VALUE, 0x160, 0x530, 0x532, 0x538)
BLOCK_LAYOUT = Layout(0, 32, 0x168, BLOCK_VALUE, 0x160, 0xC10, 0xC12, 0xC18)
SEEN_LAYOUT = Layout(0, 32, 0x16C, 1, 0x160, 0x168, 0x16A, 0x178)


class Block:
    def __init__(self, key, round_number, parent, hashes=(), time=(BLOCK_TIME_DAY, 0), qc_round=None):
        self.key, self.round, self.parent, self.hashes, self.time = key, round_number, parent, tuple(hashes), time
        self.qc_round = round_number - 1 if qc_round is None else qc_round


class Tx:
    def __init__(self, key, time=(DATE, 40000, 0), size=100, tag=0x40, byte=1):
        self.key, self.time, self.size, self.tag, self.byte = key, time, size, tag, byte


class Case:
    def __init__(self, name, **fields):
        self.name = name
        self.blocks = []
        self.txs = []
        self.watermark = 100
        self.now = (DATE, 40000, 500000000)
        self.wall = (DATE, 50000, 250000000)
        self.prev_block = None
        self.prev_wall = None
        self.throttle = {}
        self.seen = {}
        self.deque_head = 0
        self.limit = 100000
        self.__dict__.update(fields)


def chain(start, count, first=0x7000, step=0x10, gap=1, hashes=None, time=(BLOCK_TIME_DAY, 0)):
    """Blocks oldest first; each one's QC hash is the block before it, the first points at key first - step."""
    rows = []
    for index in range(count):
        key = first + step * index
        rows.append(Block(key, start + gap * index, key - step, () if hashes is None else hashes[index], (time[0] + index, time[1])))
    return rows


def key_bytes(key):
    return key.to_bytes(32, "big")


def signature_of(key):
    return (key_bytes(key) + bytes(range(0x20, 0x48)))


def qc_words(key):
    return tuple((key * 0x10001 + index + 1) & U64_MAX for index in range(5))


def sat_inc(value):
    return min(value + 1, U64_MAX)


def time_less(left, right):
    return left < right


def add_seconds(time, seconds):
    """Rule of the chrono calls at 0x489b707 and 0x489b75d, inside one year."""
    date, secs, nanos = time
    secs += seconds
    if secs >= 86400:
        return (date + 16, secs - 86400, nanos)
    return (date, secs, nanos)


def day_number(date):
    return date >> 4


def seconds_between(left, right):
    """Rule of 0x1447130: 0.0 when left is earlier, else whole microseconds over 1e6."""
    if left < right:
        return 0.0
    total = (day_number(left[0]) - day_number(right[0])) * 86400 * 10 ** 9 + (left[1] - right[1]) * 10 ** 9 + left[2] - right[2]
    return float(total // 1000) / 1000000.0


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_MEMCPY: self.on_memcpy, SLOT_ALLOC: self.on_alloc, SLOT_DEALLOC: self.on_nothing, SLOT_GROW_HASHES: self.on_grow_32, SLOT_GROW_BLOCK_HASHES: self.on_grow_32,
                 SLOT_GROW_COMMITTED: self.on_grow_32, SLOT_GROW_OUT: self.on_refuse, SLOT_GROW_DROPPED: self.on_grow_dropped, SLOT_GROW_DEQUE: self.on_refuse, SLOT_BTREE_PANIC: self.on_panic, SLOT_WALL: self.on_wall,
                 SLOT_TIME_ADD: self.on_time_add, SLOT_DATE_ADD: self.on_date_add, SLOT_LAZY: self.on_lazy, SLOT_ADD_SECS: self.on_add_secs, SLOT_SIGNED: self.on_signed, SLOT_FORMAT: self.on_format,
                 SLOT_LOCK_WAIT: self.on_refuse, SLOT_LOCK_WAKE: self.on_refuse}
        for index, (slot, hook) in enumerate(sorted(hooks.items())):
            mark = MARK_BASE + index * 16
            memory.statics[slot] = mark
            machine.slots[mark] = hook
        memory.statics[SLOT_TIME_SUB] = TIME_SUB
        memory.statics[ONCE_WORD] = 0
        machine.real = frozenset(STATIC_FUNCTIONS)
        machine.calls = {0x454C050: self.on_digest, 0x44C52B0: self.on_block_clone, 0x4847500: self.on_vector_clone, 0x4851A70: self.on_nothing, 0x470AD70: self.on_log_committed, 0x470B4C0: self.on_log_txs,
                         0x470B860: self.on_log_blocks, 0x470CBC0: self.on_log_ask, 0x4A112A0: self.on_stat, 0x4A11410: self.on_sample, 0x42B27E0: self.on_remove_tx, 0x42B2030: self.on_remove_tx,
                         0x42B43B0: self.on_remove_block, 0x4480730: self.on_nothing, 0x447E5C0: self.on_nothing, 0x44C6E70: self.on_nothing, 0x42B91F0: self.on_search, 0x4958740: self.on_entry,
                         0x4235420: self.on_kind_insert, 0x495A2E0: self.on_seen_new, 0x49460D0: self.on_seen_remove, 0x454F5D0: self.on_reserve}
        machine.step_limit = STEP_LIMIT
        self.case = None
        self.bump = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("fixture heap exhausted")
        return at

    def on_nothing(self, machine):
        pass

    def on_refuse(self, machine):
        raise Halt("edge the fixtures must not reach")

    def on_panic(self, machine):
        raise Panicked("panic")

    def on_alloc(self, machine):
        machine.regs[RAX] = self.alloc(machine.regs[RDI])

    def on_memcmp(self, machine):
        regs = machine.regs
        left = machine.memory.bytes_at(regs[RDI], regs[RDX])
        right = machine.memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def grow(self, machine, size):
        regs, memory = machine.regs, machine.memory
        vector = regs[RDI]
        cap, pointer = memory.read(vector, 8), memory.read(vector + 8, 8)
        new = max(4, cap * 2)
        at = self.alloc(new * size)
        if cap:
            memory.copy(at, pointer, cap * size)
        memory.write(vector, 8, new)
        memory.write(vector + 8, 8, at)

    def on_grow_32(self, machine):
        self.grow(machine, 32)

    def on_reserve(self, machine):
        self.grow(machine, machine.regs[R8])

    def on_grow_dropped(self, machine):
        self.grow(machine, 0x2C)

    def on_wall(self, machine):
        date, secs, nanos = self.case.wall
        machine.memory.put_bytes(machine.regs[RDI], struct.pack("<iII", date, secs + self.walls, nanos))
        self.walls += 1

    def on_time_add(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDX] == TX_KEEP_SECONDS and regs[RCX] & MASK[4] == 0, "time delta is 20 s")
        secs, nanos = struct.unpack("<II", memory.bytes_at(regs[RSI], 8))
        total = secs + regs[RDX]
        over = 86400 if total >= 86400 else 0
        memory.put_bytes(regs[RDI], struct.pack("<IIq", total - over, nanos, over))

    def on_date_add(self, machine):
        regs = machine.regs
        days = regs[RSI] & MASK[4]
        self.expect(days in (0, 1), "whole days")
        regs[RAX] = (regs[RDI] & MASK[4]) + (days << 4)

    def on_lazy(self, machine):
        self.trace.append(("lazy",))

    def on_add_secs(self, machine):
        regs, memory = machine.regs, machine.memory
        seconds = to_float(machine.xmm[0] & MASK[8])
        self.trace.append(("wait", seconds))
        date, secs, nanos = struct.unpack("<iII", memory.bytes_at(regs[RSI], 12))
        total = secs * 10 ** 9 + nanos + int(seconds * 1e9)
        memory.put_bytes(regs[RDI], struct.pack("<iII", date, total // 10 ** 9, total % 10 ** 9))

    def on_signed(self, machine):
        regs, memory = machine.regs, machine.memory
        left = struct.unpack("<iII", memory.bytes_at(regs[RDI], 12))
        right = struct.unpack("<iII", memory.bytes_at(regs[RSI], 12))
        total = (day_number(left[0]) - day_number(right[0])) * 86400 * 10 ** 9 + (left[1] - right[1]) * 10 ** 9 + left[2] - right[2]
        regs[RAX] = (total // 10 ** 9) & MASK[8]
        regs[RDX] = total % 10 ** 9
        machine.keep_rdx = True

    def on_format(self, machine):
        machine.memory.write(machine.regs[RDI], 8, 0)

    def on_digest(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(memory.read(regs[RSI], 8) == 0, "digest variant word")
        pointer = memory.read(regs[RSI] + 8, 8)
        self.expect(pointer in self.block_at, "digest of a stored block")
        memory.put_bytes(regs[RDI], key_bytes(self.block_at[pointer]))

    def on_block_clone(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], 0xB0)
        regs[RAX] = regs[RDI]

    def on_vector_clone(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], 24)
        regs[RAX] = regs[RDI]

    def text_at(self, pair):
        memory = self.machine.memory
        return memory.bytes_at(memory.read(pair, 8), memory.read(pair + 8, 8)).decode()

    def hashes(self, vector):
        memory = self.machine.memory
        pointer, count = memory.read(vector + 8, 8), memory.read(vector + 16, 8)
        return [int.from_bytes(memory.bytes_at(pointer + 32 * index, 32), "big") for index in range(count)]

    def on_log_committed(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE + 0xA8, "log target")
        at = regs[RDX]
        self.expect((self.text_at(at + 0x18), self.text_at(at + 0x28), self.text_at(at + 0x38)) == ("committed", "block hashes", "tx hashes"), "log labels")
        self.trace.append(("committed", self.hashes(at), self.hashes(memory.read(at + 0x48, 8))))

    def on_log_txs(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == STATE + 0xA8 and self.text_at(regs[RDX]) == "dropping txs", "drop log")
        at = regs[RDX] + 0x10
        pointer, count = memory.read(at + 8, 8), memory.read(at + 16, 8)
        rows = []
        for index in range(count):
            row = memory.bytes_at(pointer + 0x2C * index, 0x2C)
            rows.append((struct.unpack("<iII", row[:12]), int.from_bytes(row[12:], "big")))
        self.trace.append(("dropping txs", rows))

    def on_log_blocks(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == STATE + 0xA8 and self.text_at(regs[RDX]) == "dropping blocks", "drop log")
        self.trace.append(("dropping blocks", self.hashes(regs[RDX] + 0x10)))

    def key_at(self, at):
        memory = self.machine.memory
        self.expect(memory.read(at, 1) == 1, "request tag byte")
        return memory.read(at + 8, 8), int.from_bytes(memory.bytes_at(at + 0x10, 32), "big")

    def on_log_ask(self, machine):
        regs, memory = machine.regs, machine.memory
        at = regs[RDX]
        self.expect(regs[RSI] == OBJ_ASK + 0x18 and self.text_at(at) == "Making request after wait duration", "request log")
        self.trace.append(("making request", self.key_at(memory.read(at + 0x10, 8)), to_float(memory.read(at + 0x18, 8))))

    def on_stat(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == OBJ_STAT + 0x18, "stat object")
        self.trace.append(("stat", regs[RSI] & MASK[4], regs[RDX]))

    def on_sample(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] in (OBJ_LOG + 0x18, OBJ_LAT + 0x18), "sample object")
        self.trace.append(("sample", "log" if regs[RDI] == OBJ_LOG + 0x18 else "latency", regs[RSI] & MASK[4], to_float(machine.xmm[0] & MASK[8])))

    def on_remove_tx(self, machine):
        regs, memory = machine.regs, machine.memory
        node, height, index = (memory.read(regs[RSI] + 8 * at, 8) for at in range(3))
        self.expect(height == 0, "remove from a leaf only")
        layout = TX_LAYOUT
        count = memory.read(node + layout.len_at, 2)
        out = regs[RDI]
        memory.copy(out, node + 32 * index, 32)
        memory.copy(out + 32, node + layout.val_at + TX_VALUE * index, TX_VALUE)
        for at in range(index, count - 1):
            memory.copy(node + 32 * at, node + 32 * (at + 1), 32)
            memory.copy(node + layout.val_at + TX_VALUE * at, node + layout.val_at + TX_VALUE * (at + 1), TX_VALUE)
        memory.write(node + layout.len_at, 2, count - 1)
        memory.write(out + 0x78, 8, node)
        memory.write(out + 0x80, 8, 0)
        memory.write(out + 0x88, 8, index)

    def on_remove_block(self, machine):
        regs, memory = machine.regs, machine.memory
        node, height, index = (memory.read(regs[RSI] + 8 * at, 8) for at in range(3))
        layout = BLOCK_LAYOUT
        out = regs[RDI]
        self.dropped_blocks.add(int.from_bytes(memory.bytes_at(node + 32 * index, 32), "big"))
        memory.copy(out, node + 32 * index, 32)
        memory.copy(out + 32, node + layout.val_at + BLOCK_VALUE * index, BLOCK_VALUE)
        index += 1
        while height:
            node = memory.read(node + layout.edges_at + 8 * index, 8)
            index = 0
            height -= 1
        memory.write(out + 0x118, 8, node)
        memory.write(out + 0x120, 8, 0)
        memory.write(out + 0x128, 8, index)

    def on_search(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RSI] == memory.read(STATE + 0x1D0, 8) and regs[RDX] == memory.read(STATE + 0x1D8, 8), "throttle root")
        found = self.key_at(regs[RCX]) in self.rows
        memory.write(regs[RDI], 1, 0 if found else 1)
        memory.put_bytes(regs[RDI] + 8, bytes(24))

    def on_entry(self, machine):
        regs, memory = machine.regs, machine.memory
        context = regs[RSI]
        self.expect(memory.read(context, 8) == STATE + 0x180 and memory.read(context + 8, 8) == STATE + 0x190, "entry context")
        key = self.key_at(memory.read(context + 16, 8))
        occupied = memory.read(regs[RDI], 1) == 2
        self.expect(occupied == (key in self.rows), "entry kind")
        if not occupied:
            row = self.alloc(0x28)
            memory.put_bytes(row, bytes(24))
            memory.copy(row + 0x18, memory.read(context + 24, 8), 12)
            memory.write(row + 0x24, 4, 0)
            self.rows[key] = row
            memory.write(STATE + 0x1D0, 8, THROTTLE_ROOT)
            memory.write(STATE + 0x1E0, 8, memory.read(STATE + 0x1E0, 8) + 1)
            self.trace.append(("registering", key))
        regs[RAX] = self.rows[key]

    def on_kind_insert(self, machine):
        regs, memory = machine.regs, machine.memory
        node, index = memory.read(regs[RSI], 8), memory.read(regs[RSI] + 16, 8)
        count = memory.read(node + 0xA, 2)
        self.expect(count < 11, "reason node has room")
        data = bytearray(memory.bytes_at(node + 0xC, 11))
        data[index:index] = bytes([regs[RDX] & 0xFF])
        memory.put_bytes(node + 0xC, bytes(data[:11]))
        memory.write(node + 0xA, 2, count + 1)

    def on_seen_new(self, machine):
        regs, memory = machine.regs, machine.memory
        context = regs[RSI]
        key = int.from_bytes(memory.bytes_at(context + 8, 32), "big")
        self.expect(memory.read(context, 8) == STATE + 0x58, "seen map")
        self.trace.append(("seen new", key, regs[RDX] & 0xFF))
        self.seen_extra[key] = regs[RDX] & 0xFF
        memory.write(STATE + 0x68, 8, memory.read(STATE + 0x68, 8) + 1)

    def on_seen_remove(self, machine):
        regs, memory = machine.regs, machine.memory
        self.expect(regs[RDI] == STATE + 0x58, "seen map")
        key = int.from_bytes(memory.bytes_at(regs[RSI], 32), "big")
        self.trace.append(("seen evict", key))
        self.seen_extra.pop(key, None)
        self.seen_gone.add(key)
        memory.write(STATE + 0x68, 8, memory.read(STATE + 0x68, 8) - 1)

    def build(self, layout, items):
        """Write items, sorted, as one leaf or one root over leaves; returns (root, height)."""
        if not items:
            return 0, 0
        memory = self.machine.memory

        def node(rows, edges=()):
            at = self.alloc(layout.size)
            memory.put_bytes(at, b"\xee" * layout.size)
            memory.write(at + layout.parent_at, 8, 0)
            memory.write(at + layout.len_at, 2, len(rows))
            for index, (key, value) in enumerate(rows):
                memory.put_bytes(at + layout.key_at + layout.key_size * index, key.to_bytes(layout.key_size, "big"))
                memory.put_bytes(at + layout.val_at + layout.val_size * index, value)
            for index, child in enumerate(edges):
                memory.write(at + layout.edges_at + 8 * index, 8, child)
                memory.write(child + layout.parent_at, 8, at)
                memory.write(child + layout.pidx_at, 2, index)
            return at

        if len(items) <= 11:
            return node(items), 0
        leaves = (len(items) + 12) // 12
        each = (len(items) - (leaves - 1)) // leaves
        spare = (len(items) - (leaves - 1)) % leaves
        children, parents, at = [], [], 0
        for index in range(leaves):
            count = each + (1 if index < spare else 0)
            children.append(node(items[at:at + count]))
            at += count
            if index + 1 < leaves:
                parents.append(items[at])
                at += 1
        return node(parents, children), 1

    def tx_value(self, item):
        memory = self.machine.memory
        size_at = SIZES + self.sizes * 0x30
        self.sizes += 1
        memory.write(size_at, 8, 1)
        memory.write(size_at + 0x20, 8, item.size)
        self.size_at[item.key] = size_at
        value = bytearray(b"\xdd" * TX_VALUE)
        value[0:12] = struct.pack("<iII", *item.time)
        struct.pack_into("<Q", value, 0x10, item.tag)
        struct.pack_into("<Q", value, 0x48, size_at)
        value[0x50] = 0
        value[0x51] = item.byte
        return bytes(value)

    def block_value(self, row):
        memory = self.machine.memory
        hashes = self.alloc(max(len(row.hashes), 1) * 32)
        for index, key in enumerate(row.hashes):
            memory.put_bytes(hashes + 32 * index, key_bytes(key))
        value = bytearray(b"\xcc" * BLOCK_VALUE)
        struct.pack_into("<QQQ", value, 0, len(row.hashes), hashes, len(row.hashes))
        struct.pack_into("<QQQQQ", value, 0x18, *qc_words(row.key))
        struct.pack_into("<Q", value, 0x40, row.qc_round)
        value[0x48:0x68] = key_bytes(row.parent)
        struct.pack_into("<Q", value, 0x68, NONE_TAG)
        struct.pack_into("<Q", value, 0x88, row.round)
        value[0x90:0x9C] = struct.pack("<iII", DATE, row.time[0], row.time[1])
        value[0xB0:0xF8] = signature_of(row.key)
        return bytes(value)

    def set_state(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        self.bump = NODES
        self.trace, self.sizes, self.walls = [], 0, 0
        self.size_at, self.block_at, self.rows = {}, {}, {}
        self.dropped_blocks, self.seen_extra, self.seen_gone = set(), {}, set()
        self.case = case
        memory.put_bytes(STATE, STATE_FILL)
        for at in (OBJ_ASK, OBJ_LOG, OBJ_STAT, OBJ_LAT):
            memory.put_bytes(at, bytes(0x40))

        def word(offset, value):
            memory.write(STATE + offset, 8, value)
        word(0x180, OBJ_ASK)
        word(0x188, OBJ_LOG)
        word(0x190, OBJ_STAT)
        word(0x908, OBJ_LAT)
        word(0x198, case.watermark)
        rows = sorted(case.txs, key=lambda item: item.key)
        root, height = self.build(TX_LAYOUT, [(item.key, self.tx_value(item)) for item in rows])
        word(0x1A0, root)
        word(0x1A8, height)
        word(0x1B0, len(rows))
        rows = sorted(case.blocks, key=lambda item: item.key)
        root, height = self.build(BLOCK_LAYOUT, [(row.key, self.block_value(row)) for row in rows])
        word(0x1B8, root)
        word(0x1C0, height)
        word(0x1C8, len(rows))
        self.index_blocks(root, height)
        self.set_throttle(case)
        word(0x1D8, 0)
        word(0x1E0, len(case.throttle))
        word(0x38, DEQUE_CAP)
        word(0x40, DEQUE)
        word(0x48, case.deque_head)
        keys = sorted(case.seen)
        word(0x50, len(keys))
        for index, key in enumerate(keys):
            memory.put_bytes(DEQUE + 32 * ((case.deque_head + index) % DEQUE_CAP), key_bytes(key))
        root, height = self.build(SEEN_LAYOUT, [(key, bytes([case.seen[key]])) for key in keys])
        word(0x58, root)
        word(0x60, height)
        word(0x68, len(keys))
        word(0x70, case.limit)
        memory.put_bytes(STATE + 0xAC8, struct.pack("<iII", *case.now))
        memory.put_bytes(STATE + 0xAD4, struct.pack("<iII", *case.prev_block) if case.prev_block else bytes(12))
        memory.put_bytes(STATE + 0xAE0, struct.pack("<iII", *case.prev_wall) if case.prev_wall else bytes(12))
        word(0x4D0, OUTBOX_CAP)
        word(0x4D8, OUTBOX)
        word(0x4E0, 0)

    def set_throttle(self, case):
        memory = self.machine.memory
        memory.write(STATE + 0x1D0, 8, THROTTLE_ROOT if case.throttle else 0)
        for key, (time, sent, kinds) in sorted(case.throttle.items()):
            row = self.alloc(0x28)
            memory.put_bytes(row, bytes(24))
            if kinds:
                node = self.alloc(0x18)
                memory.put_bytes(node, bytes(0x18))
                memory.write(node + 0xA, 2, len(kinds))
                memory.put_bytes(node + 0xC, bytes(sorted(kinds)))
                memory.write(row, 8, node)
                memory.write(row + 16, 8, len(kinds))
            memory.put_bytes(row + 0x18, struct.pack("<iII", *time))
            memory.write(row + 0x24, 4, 1 if sent else 0)
            self.rows[key] = row

    def index_blocks(self, root, height):
        memory = self.machine.memory
        layout = BLOCK_LAYOUT

        def walk(node, depth):
            count = memory.read(node + layout.len_at, 2)
            for index in range(count):
                self.block_at[node + layout.val_at + BLOCK_VALUE * index] = int.from_bytes(memory.bytes_at(node + 32 * index, 32), "big")
            if depth:
                for index in range(count + 1):
                    walk(memory.read(node + layout.edges_at + 8 * index, 8), depth - 1)
        if root:
            walk(root, height)

    def run(self, case):
        machine = self.machine
        memory = machine.memory
        self.set_state(case)
        machine.xmm = [POISON | POISON << 64] * 16
        before = bytes(memory.bytes_at(STATE, STATE_SIZE))
        panicked = False
        try:
            machine.run(COMMIT, {RDI: STATE})
        except Panicked:
            panicked = True
        return self.observe(before, panicked)

    def map_keys(self, root_at, height_at, layout):
        memory = self.machine.memory
        keys = []

        def walk(node, depth):
            count = memory.read(node + layout.len_at, 2)
            for index in range(count):
                if depth:
                    walk(memory.read(node + layout.edges_at + 8 * index, 8), depth - 1)
                keys.append(int.from_bytes(memory.bytes_at(node + 32 * index, 32), "big"))
            if depth:
                walk(memory.read(node + layout.edges_at + 8 * count, 8), depth - 1)
        root = memory.read(STATE + root_at, 8)
        if root:
            walk(root, memory.read(STATE + height_at, 8))
        return keys

    def seen_bytes(self):
        """Key to value byte of the seen map fixture."""
        memory = self.machine.memory
        root = memory.read(STATE + 0x58, 8)
        out = {}
        if root:
            for index in range(memory.read(root + SEEN_LAYOUT.len_at, 2)):
                key = int.from_bytes(memory.bytes_at(root + 32 * index, 32), "big")
                if key not in self.seen_gone:
                    out[key] = memory.read(root + SEEN_LAYOUT.val_at + index, 1)
        out.update(self.seen_extra)
        return out

    def commit_row(self, at):
        memory = self.machine.memory
        arc, txs = memory.read(at, 8), memory.read(at + 8, 8)
        block = arc + 0x10
        proof = arc + 0x108
        row = dict(strong=(memory.read(arc, 8), memory.read(arc + 8, 8)), key=int.from_bytes(memory.bytes_at(block + 0xB0, 32), "big"), round=memory.read(block + 0x88, 8),
                   qc_hash=int.from_bytes(memory.bytes_at(block + 0x48, 32), "big"), time=struct.unpack("<iII", memory.bytes_at(at + 16, 12)))
        if memory.read(proof, 8) == NONE_TAG:
            row["proof"] = None
        else:
            row["proof"] = dict(child=int.from_bytes(memory.bytes_at(proof + 0xB0, 32), "big"), child_round=memory.read(proof + 0x88, 8), words=tuple(memory.read(proof + 0xF8 + 8 * index, 8) for index in range(5)),
                                qc_round=memory.read(proof + 0x120, 8), qc_hash=int.from_bytes(memory.bytes_at(proof + 0x128, 32), "big"))
        count, pointer = memory.read(txs + 0x20, 8), memory.read(txs + 0x18, 8)
        row["txs"] = [(int.from_bytes(memory.bytes_at(pointer + 40 * index, 32), "big"), memory.read(memory.read(pointer + 40 * index + 32, 8) + 0x20, 8)) for index in range(count)]
        return row

    def observe(self, before, panicked):
        memory = self.machine.memory
        after = memory.bytes_at(STATE, STATE_SIZE)
        changed = sorted({index & ~7 for index in range(0, STATE_SIZE) if before[index] != after[index]}) if before != after else []
        out = []
        for index in range(struct.unpack_from("<Q", after, 0x4E0)[0]):
            record = OUTBOX + RECORD * index
            tag = memory.read(record, 8)
            if tag == 3:
                out.append(("commit", self.commit_row(record + 8)))
            elif tag == 10:
                out.append(("ask", memory.read(record + 8, 1), memory.read(record + 0x10, 8), int.from_bytes(memory.bytes_at(record + 0x18, 32), "big")))
            else:
                out.append((tag,))
        count, head = struct.unpack_from("<Q", after, 0x50)[0], struct.unpack_from("<Q", after, 0x48)[0]
        deque = [int.from_bytes(memory.bytes_at(DEQUE + 32 * ((head + index) % DEQUE_CAP), 32), "big") for index in range(count)]
        rows = {}
        for key, row in self.rows.items():
            kinds = []
            node = memory.read(row, 8)
            if node:
                kinds = list(memory.bytes_at(node + 0xC, memory.read(node + 0xA, 2)))
            rows[key] = (struct.unpack("<iII", memory.bytes_at(row + 0x18, 12)), memory.read(row + 0x24, 1), kinds)
        return dict(panicked=panicked, watermark=struct.unpack_from("<Q", after, 0x198)[0], out=out, trace=list(self.trace), changed=changed, tx_count=struct.unpack_from("<Q", after, 0x1B0)[0], block_count=struct.unpack_from("<Q", after, 0x1C8)[0],
                    tx_keys=self.map_keys(0x1A0, 0x1A8, TX_LAYOUT), block_keys=[key for key in self.map_keys(0x1B8, 0x1C0, BLOCK_LAYOUT) if key not in self.dropped_blocks], deque=deque, seen=self.seen_bytes(), throttle=rows,
                    prev_block=struct.unpack("<iII", after[0xAD4:0xAE0]), prev_wall=struct.unpack("<iII", after[0xAE0:0xAEC]))


def spec_ask(case, want, kind, key_hash, label):
    """The throttle rule: one row per (watermark, hash), a request only 1.0 s after the row's stamp and only once."""
    key = (case.watermark, key_hash)
    rows = want["throttle"]
    root_was_empty = not rows
    if key not in rows:
        rows[key] = (case.now, 0, [])
        want["trace"].append(("registering", key))
        want["changed"].add(0x1E0)
        if root_was_empty:
            want["changed"].add(0x1D0)
    time, sent, kinds = rows[key]
    if kind not in kinds:
        kinds = sorted(kinds + [kind])
    want["trace"].append(("wait", ASK_WAIT))
    date, secs, nanos = time
    rows[key] = (time, sent, kinds)
    if case.now < (date, secs + int(ASK_WAIT), nanos) or sent:
        return label + ", no request"
    want["trace"].append(("making request", key, ASK_WAIT))
    want["trace"].append(("stat", 5, 1))
    rows[key] = (time, 1, kinds)
    want["out"].append(("ask", 1, case.watermark, key_hash))
    want["changed"].add(0x4E0)
    return label + ", request"


def spec_run(case):
    """The written rules, without any instruction row. Returns (label, observation)."""
    blocks = {row.key: row for row in case.blocks}
    txs = {item.key: item for item in case.txs}
    want = dict(panicked=False, watermark=case.watermark, out=[], trace=[], changed=set(), tx_count=len(txs), block_count=len(blocks), tx_keys=sorted(txs), block_keys=sorted(blocks),
                deque=sorted(case.seen), seen=dict(case.seen), throttle={key: (row[0], 1 if row[1] else 0, sorted(row[2])) for key, row in case.throttle.items()},
                prev_block=case.prev_block or (0, 0, 0), prev_wall=case.prev_wall or (0, 0, 0))

    def done(label):
        want["changed"] = sorted(want["changed"])
        return label, want
    if not blocks:
        return done("no blocks")
    tip = max(sorted(blocks.values(), key=lambda row: row.key), key=lambda row: row.round)
    for row in sorted(blocks.values(), key=lambda row: row.key):
        if row.round >= tip.round:
            tip = row
    child = blocks.get(tip.parent)
    if child is None:
        return done(spec_ask(case, want, 0, tip.parent, "tip parent missing"))
    start = blocks.get(child.parent)
    if start is None:
        return done(spec_ask(case, want, 0, child.parent, "second parent missing"))
    if child.round != sat_inc(start.round):
        return done("rounds not consecutive")
    grand, record_rows, count_txs, count_bytes = tip, [], 0, 0
    block_hashes, tx_hashes, current = [], [], start
    if start.round > case.watermark:
        while True:
            missing = [key for key in current.hashes if key not in txs or txs[key].tag == TX_SKIP_TAG]
            if missing:
                return done(spec_ask(case, want, 1, current.key, "tx missing"))
            count_txs = min(count_txs + len(current.hashes), U64_MAX)
            for key in current.hashes:
                count_bytes = min(count_bytes + txs[key].size, U64_MAX)
            record_rows.append((current, child if child.round == sat_inc(current.round) else None, grand))
            tx_hashes.extend(current.hashes)
            block_hashes.append(current.key)
            parent = blocks.get(current.parent)
            if parent is None:
                want["trace"].append(("lazy",))
                return done(spec_ask(case, want, 2, current.parent, "ancestor missing"))
            grand, child, current = child, current, parent
            if current.round <= case.watermark:
                break
    if current.round != case.watermark:
        return done("walk passed the watermark")
    if start.round != case.watermark:
        want["changed"].add(0x198)
    want["watermark"] = start.round
    trace = want["trace"]
    if record_rows:
        trace.append(("stat", 0, len(record_rows)))
        trace.append(("stat", 1, min(count_txs, I64_MAX)))
        trace.append(("stat", 2, min(count_bytes, I64_MAX)))
        trace.append(("committed", block_hashes, tx_hashes))
    live = dict(txs)
    deque = list(want["deque"])
    head = case.deque_head
    seen = want["seen"]
    for key in tx_hashes:
        item = live.pop(key, None)
        if item is None:
            continue
        trace.append(("sample", "log", 0x12, seconds_between(case.now, item.time)))
        if key in seen:
            seen[key] = item.byte
        else:
            trace.append(("seen new", key, item.byte))
            seen[key] = item.byte
            deque.append(key)
            want["changed"].update((0x50, 0x68))
        while len(deque) > case.limit:
            gone = deque.pop(0)
            head = (head + 1) % DEQUE_CAP
            del seen[gone]
            trace.append(("seen evict", gone))
            want["changed"].update((0x48, 0x50, 0x68))
    want["deque"] = deque
    if head == case.deque_head:
        want["changed"].discard(0x48)
    if len(deque) == len(case.seen):
        want["changed"].discard(0x50)
        want["changed"].discard(0x68)
    size_after = len(live)
    dropped = [(live[key].time, key) for key in sorted(live) if add_seconds(live[key].time, TX_KEEP_SECONDS) < case.now]
    for _, key in dropped:
        del live[key]
    if dropped:
        trace.append(("dropping txs", dropped))
        trace.append(("stat", 3, len(dropped)))
    gone = [key for key in sorted(blocks) if blocks[key].round < start.round]
    if gone:
        trace.append(("dropping blocks", gone))
        want["changed"].add(0x1C8)
    if len(live) != len(txs):
        want["changed"].add(0x1B0)
    want["tx_count"] = len(live)
    want["tx_keys"] = sorted(live)
    want["block_keys"] = [key for key in sorted(blocks) if key not in gone]
    want["block_count"] = len(want["block_keys"])
    if not record_rows:
        return done("nothing to commit, pruned")
    previous_time, previous_wall = want["prev_block"], want["prev_wall"]
    wall = case.wall
    for index, (row, proof, witness) in enumerate(reversed(record_rows)):
        time = (DATE, row.time[0], row.time[1])
        now = (wall[0], wall[1] + index, wall[2])
        if previous_time[0] == 0:
            previous_time = time
        if previous_wall[0] == 0:
            previous_wall = now
        trace.append(("sample", "latency", 0x10, seconds_between(time, previous_time)))
        trace.append(("sample", "latency", 0x11, seconds_between(now, previous_wall)))
        previous_time, previous_wall = time, now
        entry = dict(strong=(1, 1), key=row.key, round=row.round, qc_hash=row.parent, time=time, proof=None, txs=[(key, txs[key].size) for key in row.hashes])
        if proof is not None:
            entry["proof"] = dict(child=proof.key, child_round=proof.round, words=qc_words(witness.key), qc_round=witness.qc_round, qc_hash=witness.parent)
        want["out"].append(("commit", entry))
    for at, old, new in ((0xAD4, want["prev_block"], previous_time), (0xAE0, want["prev_wall"], previous_wall)):
        for index, (left, right) in enumerate(zip(struct.pack("<iII", *old), struct.pack("<iII", *new))):
            if left != right:
                want["changed"].add((at + index) & ~7)
    want["prev_block"], want["prev_wall"] = previous_time, previous_wall
    want["changed"].add(0x4E0)
    return done("committed")


def same(got, want):
    keys = sorted(set(got) | set(want))
    return [key for key in keys if got.get(key) != want.get(key)]


PINS = (
    ("caller", 0x44ae320, "e84bd6ffff", "tx arm calls the walk"),
    ("caller", 0x44b04ab, "0f8541130000", "block arm, error tag jump"),
    ("caller", 0x44b04c5, "0f820f130000", "block arm, round compare jump"),
    ("caller", 0x44b12e6, "e914050000", "block arm, ok tail jump"),
    ("caller", 0x44b1802, "e869a1ffff", "shared tail calls the walk"),
    ("tip", 0x44ab9bf, "0f85d9120000", "empty map returns"),
    ("tip", 0x44abb6f, "498bb788000000", "round of the first entry"),
    ("tip", 0x44abb9c, "488b9417f0010000", "round of the next entry"),
    ("tip", 0x44abba7, "4d0f46f9", "cmovbe: a later entry wins a tie"),
    ("tip", 0x44abccd, "410f104748", "tip QC hash, first half"),
    ("chain", 0x44abd8e, "0f82930e0000", "tip parent lookup fails to the ask"),
    ("chain", 0x44abdb2, "0f1043c0", "child QC hash, first half"),
    ("chain", 0x44abe5c, "0f82c50d0000", "second lookup fails to the ask"),
    ("chain", 0x44abe81, "48ffc0", "start round plus 1"),
    ("chain", 0x44abe8b, "480f45c8", "saturating at u64 max"),
    ("chain", 0x44abe8f, "48390b", "child round compare"),
    ("chain", 0x44abe9f, "0f85f90d0000", "not consecutive: return"),
    ("walk", 0x44abf47, "498b8698010000", "committed round read"),
    ("walk", 0x44abf56, "0f8640090000", "start at or under the committed round"),
    ("walk", 0x44ac0dd, "48394500", "tag compare"),
    ("walk", 0x44ac0e9, "0f84e60a0000", "tag ...01: missing"),
    ("walk", 0x44ac170, "e87b443100", "collect txs"),
    ("walk", 0x44ac2d4, "48398688000000", "child round against walked round + 1"),
    ("walk", 0x44ac2e3, "0f85fb030000", "no proof when not consecutive"),
    ("walk", 0x44ac6e4, "48b80000000000000080", "proof None word"),
    ("walk", 0x44ac6ee, "4889842448050000", "stored in the proof"),
    ("walk", 0x44ac6c4, "4839c1", "parent round against the committed round"),
    ("walk", 0x44ac6d9, "0f879af8ffff", "walk continues"),
    ("walk", 0x44ac8b4, "0f853e040000", "stop above or below: drop everything"),
    ("walk", 0x44ac8cf, "488901", "committed round written"),
    ("walk", 0x44ac8d8, "0f843f060000", "no record: prune only"),
    ("sums", 0x44ac257, "490f42d5", "tx count saturates"),
    ("sums", 0x44ac2a5, "490f42c5", "byte count saturates"),
    ("sums", 0x44ac913, "49bdffffffffffffff7f", "i64 max cap of stat 1"),
    ("sums", 0x44ac93c, "4c0f42eb", "i64 max cap of stat 2"),
    ("ask", 0x44acbef, "488b742408", "ask with this state"),
    ("ask", 0x44acbf7, "41b901000000", "reason 1, tx missing"),
    ("ask", 0x44acc84, "4531c9", "reason 0, parent of tip or child"),
    ("ask", 0x44ad058, "41b902000000", "reason 2, ancestor"),
    ("ask", 0x44ad032, "ff1550242c01", "lazy global read before reason 2"),
    ("ask", 0x44acec4, "48c78424a00100000a000000", "request becomes outbox tag 0xa"),
    ("prune", 0x44acab7, "e8445a4900", "remove one tx"),
    ("prune", 0x44acad4, "4883f801", "tags ...01 and ...02 skip the sample"),
    ("prune", 0x44acb9d, "be12000000", "sample 0x12"),
    ("prune", 0x44acbb7, "488d0da2342701", "seen insert Location"),
    ("prune", 0x44ad126, "e815e53e00", "next tx past 20 s"),
    ("prune", 0x44ad436, "e885ac3e00", "next block under the committed round"),
    ("prune", 0x44ad2a4, "be03000000", "stat 3"),
    ("tx age", 0x489b6f6, "ba14000000", "20 seconds, edx of the chrono add"),
    ("tx age", 0x489b705, "31c9", "zero nanoseconds"),
    ("tx age", 0x489b76b, "413b06", "date compare"),
    ("tx age", 0x489b773, "453b6e04", "seconds compare"),
    ("tx age", 0x489b780, "413b4608", "nanoseconds compare"),
    ("tx age", 0x489b784, "730d", "at or after keeps the tx"),
    ("block age", 0x4898140, "498b9414f0010000", "block round"),
    ("block age", 0x489814b, "483b17", "compare with the committed round"),
    ("block age", 0x489814e, "0f82e4000000", "below goes out"),
    ("throttle", 0x44b8095, "c644241001", "tag byte 1"),
    ("throttle", 0x44b8078, "488b8698010000", "committed round in the key"),
    ("throttle", 0x44b820b, "41f6c501", "r8 picks the wait"),
    ("throttle", 0x44b8211, "f20f10051725d5fb", "wait 1.0"),
    ("throttle", 0x44b8272, "7306", "time compare"),
    ("throttle", 0x44b827a, "41807c242401", "sent flag"),
    ("throttle", 0x44b830b, "41c644242401", "sent flag set"),
    ("throttle", 0x44b832a, "be05000000", "stat 5"),
    ("throttle", 0x4958816, "ba01000000", "row insert stat count"),
    ("throttle", 0x495881b, "be04000000", "stat 4"),
    ("seen", 0x4356b26, "4388842c6c010000", "existing key: byte rewritten"),
    ("seen", 0x4356be3, "483b4338", "length over the limit at +0x38"),
    ("seen", 0x4356c58, "e873f45e00", "evict from the map"),
    ("seen", 0x44a8c82, "48c7842418090000a0860100", "limit 100000 at rsp+0x918, record base rsp+0x8e0"),
    ("seen", 0x44a904a, "0f118424b8030000", "record moved to rsp+0x3b8"),
    ("seen", 0x44a97b3, "488db42480030000", "state image at rsp+0x380"),
    ("seen", 0x44a97bb, "ba38020000", "first 0x238 bytes of the state"),
    ("gaps", 0x44ad5eb, "833b00", "first block time store test"),
    ("gaps", 0x44ad5f4, "41833c2400", "first wall time store test"),
    ("gaps", 0x44ad6f1, "f20f10442418", "sample 0x10"),
    ("gaps", 0x44ad704, "f20f10442430", "sample 0x11"),
    ("outbox", 0x47f5255, "48c742f803000000", "tag 3 per record"),
    ("time sub", 0x1447181, "4869c640420f00", "seconds to microseconds"),
    ("time sub", 0x144719c, "4869c9d34d6210", "nanoseconds over 1000"),
    ("time sub", 0x14471c6, "f20f5e05923cdcfe", "divide by 1e6"),
)


def survivor_reason(va, kind):
    return "the cheapest %d cases reaching this %s row do not separate the edit" % (MUTANT_CAP, kind)


def named_cases():
    now = (DATE, 40000, 500000000)
    plain = chain(100, 4)
    with_tx = chain(100, 4, hashes=[(), (0x51, 0x52), (), ()])
    keep = (DATE, 39980, 500000000)
    late = (DATE, 39980, 499999999)
    return [
        Case("no blocks"),
        Case("one block, parent absent", blocks=[Block(0x7000, 101, 0x6000)]),
        Case("row stamped exactly 1 s ago", blocks=[Block(0x7000, 101, 0x6000)], throttle={(100, 0x6000): ((DATE, 39999, 500000000), False, ())}),
        Case("row stamped 1 ns under 1 s ago", blocks=[Block(0x7000, 101, 0x6000)], throttle={(100, 0x6000): ((DATE, 39999, 500000001), False, ())}),
        Case("row already sent", blocks=[Block(0x7000, 101, 0x6000)], throttle={(100, 0x6000): ((DATE, 39000, 0), True, (0,))}),
        Case("row of an older watermark", blocks=[Block(0x7000, 101, 0x6000)], watermark=120, throttle={(100, 0x6000): ((DATE, 39000, 0), True, (0,))}),
        Case("row with another reason", blocks=[Block(0x7000, 101, 0x6000)], throttle={(100, 0x6000): ((DATE, 39000, 0), False, (1,))}),
        Case("row with both reasons", blocks=[Block(0x7000, 101, 0x6000)], throttle={(100, 0x6000): ((DATE, 39000, 0), False, (0, 2))}),
        Case("two blocks, second parent absent", blocks=[Block(0x7000, 101, 0x6000), Block(0x7010, 102, 0x7000)]),
        Case("two blocks, second parent absent, due", blocks=[Block(0x7000, 101, 0x6000), Block(0x7010, 102, 0x7000)], throttle={(100, 0x6000): ((DATE, 39000, 0), False, ())}),
        Case("three blocks, gap of 2 under the child", blocks=[Block(0x7000, 101, 0x6000), Block(0x7010, 103, 0x7000), Block(0x7020, 104, 0x7010), Block(0x6000, 100, 0x5000)]),
        Case("gap only above the child commits", blocks=[Block(0x7000, 100, 0x6000), Block(0x7010, 101, 0x7000), Block(0x7020, 102, 0x7010), Block(0x7030, 109, 0x7020)]),
        Case("one commit, child consecutive", blocks=plain),
        Case("watermark equals start", blocks=plain, watermark=101),
        Case("start under watermark", blocks=plain, watermark=102),
        Case("commit with txs", blocks=with_tx, txs=[Tx(0x51, (DATE, 40000, 0), 700), Tx(0x52, (DATE, 39999, 123456789), 900), Tx(0x53, keep)]),
        Case("three block commit", blocks=chain(100, 6, hashes=[(), (0x51,), (0x52,), (0x53,), (), ()]), txs=[Tx(0x51), Tx(0x52), Tx(0x53)]),
        Case("gap inside the walk, no proof", blocks=[Block(0x7000, 100, 0x6000), Block(0x7010, 101, 0x7000), Block(0x7020, 104, 0x7010), Block(0x7030, 105, 0x7020), Block(0x7040, 106, 0x7030), Block(0x7050, 107, 0x7040)]),
        Case("walk jumps over the watermark", blocks=[Block(0x7000, 99, 0x6000), Block(0x7010, 103, 0x7000), Block(0x7020, 104, 0x7010), Block(0x7030, 105, 0x7020)], txs=[Tx(0x51, late)]),
        Case("second tx missing", blocks=chain(100, 5, hashes=[(), (0x51,), (0x52, 0x53), (), ()]), txs=[Tx(0x52), Tx(0x51)]),
        Case("tx missing in an older block", blocks=chain(100, 5, hashes=[(), (0x51,), (0x52,), (), ()]), txs=[Tx(0x52)]),
        Case("tx with skip tag counts as missing", blocks=with_tx, txs=[Tx(0x51), Tx(0x52, tag=TX_SKIP_TAG)]),
        Case("tx missing, row due", blocks=with_tx, txs=[Tx(0x51)], throttle={(100, 0x7010): ((DATE, 39000, 0), False, ())}),
        Case("empty tx map", blocks=with_tx),
        Case("ancestor missing", blocks=chain(103, 3, first=0x7020), watermark=100),
        Case("ancestor missing, row due", blocks=chain(103, 3, first=0x7020), watermark=100, throttle={(100, 0x7010): ((DATE, 39000, 0), False, ())}),
        Case("ancestor missing after a commit candidate", blocks=chain(103, 4, first=0x7020, hashes=[(0x51,), (0x52,), (), ()]), watermark=100, txs=[Tx(0x51), Tx(0x52)]),
        Case("tie on top round, last key wins", blocks=chain(100, 4) + [Block(0x7100, 103, 0x6100)]),
        Case("tie on top round, first key would commit", blocks=[Block(0x6F00, 100, 0x6000), Block(0x6F10, 101, 0x6F00), Block(0x6F20, 102, 0x6F10), Block(0x6F30, 103, 0x6F20), Block(0x7100, 103, 0x6100)]),
        Case("fork below the new watermark dropped", blocks=chain(100, 4) + [Block(0x7200, 100, 0x6000), Block(0x7210, 101, 0x7200)]),
        Case("fork at the new watermark kept", blocks=chain(100, 4) + [Block(0x7200, 101, 0x6000)]),
        Case("old block dropped on an idle pass", blocks=chain(100, 4) + [Block(0x7200, 50, 0x6000)], watermark=101),
        Case("tx exactly 20 s old kept", blocks=plain, watermark=101, txs=[Tx(0x51, keep)]),
        Case("tx 1 ns past 20 s dropped", blocks=plain, watermark=101, txs=[Tx(0x51, late), Tx(0x52, keep)]),
        Case("two txs dropped, stat 3", blocks=plain, watermark=101, txs=[Tx(0x51, late), Tx(0x52, (DATE, 100, 0), tag=TX_SKIP_TAG), Tx(0x53)]),
        Case("tx time crosses midnight, kept", blocks=plain, watermark=101, now=(DATE + 16, 1, 0), txs=[Tx(0x51, (DATE, 86395, 0))]),
        Case("tx on the day before, dropped", blocks=plain, watermark=101, now=(DATE + 16, 40, 0), txs=[Tx(0x51, (DATE, 86395, 0))]),
        Case("tx on the next day, kept", blocks=plain, watermark=101, txs=[Tx(0x51, (DATE + 16, 0, 0))]),
        Case("key already seen, byte rewritten", blocks=with_tx, txs=[Tx(0x51, byte=0), Tx(0x52, byte=1)], seen={0x51: 1}),
        Case("seen limit evicts oldest", blocks=with_tx, txs=[Tx(0x51), Tx(0x52)], seen={0x40: 1, 0x41: 1}, limit=3),
        Case("seen limit on rewrite", blocks=with_tx, txs=[Tx(0x51), Tx(0x52)], seen={0x40: 1, 0x51: 0}, limit=1),
        Case("seen deque wraps", blocks=with_tx, txs=[Tx(0x51), Tx(0x52)], seen={0x40: 1, 0x41: 1, 0x42: 1}, deque_head=62, limit=3),
        Case("same tx in two blocks", blocks=chain(100, 5, hashes=[(), (0x51,), (0x51,), (), ()]), txs=[Tx(0x51)]),
        Case("same tx twice in a block", blocks=chain(100, 4, hashes=[(), (0x51, 0x51), (), ()]), txs=[Tx(0x51)]),
        Case("round u64 max", blocks=[Block(0x7000, U64_MAX - 1, 0x6000), Block(0x7010, U64_MAX, 0x7000), Block(0x7020, U64_MAX, 0x7010), Block(0x7030, U64_MAX, 0x7020)], watermark=U64_MAX - 1),
        Case("sizes saturate", blocks=with_tx, txs=[Tx(0x51, size=U64_MAX - 5), Tx(0x52, size=9)]),
        Case("sizes above i64 max", blocks=with_tx, txs=[Tx(0x51, size=1 << 63), Tx(0x52, size=9)]),
        Case("QC rounds ignored", blocks=[Block(0x7000, 100, 0x6000, qc_round=7), Block(0x7010, 101, 0x7000, qc_round=7), Block(0x7020, 102, 0x7010, qc_round=7), Block(0x7030, 103, 0x7020, qc_round=7)]),
        Case("gap samples with earlier state", blocks=chain(100, 5), prev_block=(DATE, 38000, 0), prev_wall=(DATE, 49000, 5000)),
        Case("block time goes backwards", blocks=chain(100, 4), prev_block=(DATE, 39999, 0), prev_wall=(DATE, 50001, 0)),
        Case("first commit sets gap state", blocks=chain(100, 5)),
        Case("tx latency keeps microseconds", blocks=with_tx, now=(DATE, 40000, 1999), txs=[Tx(0x51, (DATE, 40000, 1)), Tx(0x52, (DATE, 40001, 0))]),
        Case("twelve hashes in a two level tx map", blocks=chain(100, 3, hashes=[(), (0x90,), ()]), txs=[Tx(0x10 + index) for index in range(16)]),
        Case("two level block map, idle", blocks=chain(100, 16), watermark=113),
        Case("two level block map, commit", blocks=chain(100, 16), watermark=100),
        Case("two level block map, prune", blocks=chain(100, 16) + [Block(0x7300 + index, 90, 0x6000) for index in range(4)], watermark=113),
        Case("two level tx map, idle prune walk", blocks=plain, watermark=101, txs=[Tx(0x10 + index) for index in range(30)]),
        Case("eleven blocks in one leaf", blocks=chain(100, 11), watermark=100),
        Case("nine txs in one block", blocks=chain(100, 4, hashes=[(), tuple(range(0x51, 0x5A)), (), ()]), txs=[Tx(key) for key in range(0x51, 0x5A)]),
    ]


def lcg(seed):
    value = seed
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & U64_MAX
        yield value >> 33


def vector_cases(count):
    cases = []
    random = lcg(0x1234)
    for number in range(count):
        length = 2 + next(random) % 8
        rows, used, key, round_number = [], [], 0x7000 + 0x10 * (next(random) % 5), 100 + next(random) % 4
        parent = key - 0x10
        for index in range(length):
            hashes = tuple(0x100 + number % 40 + index * 3 + at for at in range(next(random) % 3))
            used.extend(hashes)
            rows.append(Block(key, round_number, parent, hashes, (39000 + index, next(random) % 1000)))
            parent, key = key, key + 0x10 + 0x100 * (next(random) % 3)
            round_number += 1 + (next(random) % 5 == 0)
        pool = sorted(set(used))
        txs = []
        for item in pool[:11]:
            if next(random) % 12:
                age = next(random) % 40
                txs.append(Tx(item, (DATE, 40000 - age, 500000000), 10 + next(random) % 1000, TX_SKIP_TAG if next(random) % 25 == 0 else 0x40, next(random) % 2))
        for index in range(next(random) % 3):
            txs.append(Tx(0x900 + index, (DATE, 39950 + next(random) % 60, 0)))
        if next(random) % 3 == 0:
            rows.pop(0)
        for index in range(next(random) % 3):
            rows.append(Block(0x7800 + index, 96 + next(random) % 8, 0x6000))
        watermark = 100 + next(random) % 7
        seen = {pool[0]: 0} if pool and next(random) % 3 == 0 else {}
        throttle = {}
        if next(random) % 2 and rows:
            throttle[(watermark, rows[0].parent)] = ((DATE, 39990, 0), next(random) % 3 == 0, ())
        cases.append(Case("vector %d" % number, blocks=rows, txs=txs[:11], watermark=watermark, seen=seen, throttle=throttle, limit=1 + next(random) % 6 if next(random) % 3 == 0 else 100000))
    return cases


def check_all(harness, cases):
    rows = []
    for case in cases:
        label, want = spec_run(case)
        got = harness.run(case)
        diff = same(got, want)
        if diff:
            raise EvidenceError("%s: differs in %s" % (case.name, diff))
        rows.append((case, label, got))
    return rows


CONSTANTS = ((0x20A730, 1.0, "wait passed to the throttle compare at 0x44b8211 when r8 is clear"), (0x20AE60, 1000000.0, "divisor of whole microseconds at 0x14471c6"))
STRINGS = ((0x6F4DC5, "committed"), (0x6F4DCE, "block hashes"), (0x6F4DDA, "tx hashes"), (0x6F4F07, "dropping txs"), (0x6F4E83, "dropping blocks"), (0x6F4EE5, "Making request after wait duration"), (0x701EBD, "Registering request"))
LOCATIONS = ((0x44ACBB7, 0x5720060, "rcx of seen insert 0x4356a60"),)
FILE_LINES = ((0x44ACB37, 0x6F4DE3, 0x3A, 0x19A, "tx latency, time sub"), (0x44AD62B, 0x6F4C1F, 0x38, 0x2BA, "block time gap, time sub"), (0x44AD687, 0x6F4C1F, 0x38, 0x2BB, "wall gap, time sub"))
TRIGGERS = ((0x44AE320, 0x44ADFA0, "tx arm: after 0x44b9a50, before 0x44aa5a0 and the proposer"), (0x44B1802, 0x44ADFA0, "shared tail after block registration 0x44b8410, reached by jumps at 0x44b04ab, 0x44b04c5, 0x44b12e6, before 0x44aa5a0 and the proposer"))
LAYOUT = (("block map value", 0x0, 0x18, "tx hash vector: cap, ptr, len", 0x44ABF91),
          ("block map value", 0x18, 0x50, "QC of this block; hash of the parent at +0x48", 0x44ABCCD),
          ("block map value", 0x40, 0x8, "QC round, copied into the proof, never compared here", 0x44AC34A),
          ("block map value", 0x88, 0x8, "round", 0x44ABB6F),
          ("block map value", 0x90, 0xC, "time, copied into the commit record", 0x44AC854),
          ("block map value", 0xB0, 0x48, "signature bytes, cloned with the block", 0x44AC2E9),
          ("tx map value", 0x0, 0xC, "time, read by the 20 s prune and the latency sample", 0x489B6DD),
          ("tx map value", 0x10, 0x8, "tag, 0x8000000000000001 is treated as missing", 0x44AC0D0),
          ("tx map value", 0x48, 0x8, "shared record, byte size at +0x20", 0x47C07A0),
          ("tx map value", 0x51, 0x1, "byte stored in the seen map", 0x44ACBA7),
          ("commit record, 0x20 bytes", 0x0, 0x8, "Arc: strong, weak, block 0xb0, signature 0x48, proof 0x148", 0x44AC48C),
          ("commit record, 0x20 bytes", 0x8, 0x8, "Arc of the vector of 0x28 byte tx rows", 0x44AC490),
          ("commit record, 0x20 bytes", 0x10, 0xC, "block time", 0x44AC495),
          ("proof, 0x148 bytes", 0x0, 0xB0, "child block, None word 0x8000000000000000 in the first field", 0x44AC6E4),
          ("proof, 0x148 bytes", 0xB0, 0x48, "child signature", 0x44AC2E9),
          ("proof, 0x148 bytes", 0xF8, 0x50, "QC of the grandchild, which names the child", 0x44AC33C),
          ("throttle row, 0x28 bytes", 0x0, 0x18, "set of reason bytes", 0x492D4B7),
          ("throttle row, 0x28 bytes", 0x18, 0xC, "time the row was first made", 0x44B821F),
          ("throttle row, 0x28 bytes", 0x24, 0x1, "sent flag, set once", 0x44B830B),
          ("outbox row, 0x168 bytes", 0x0, 0x8, "tag: 3 commit record, 0xa request", 0x47F5255),
          ("state", 0x38, 0x38, "seen txs: deque cap, ptr, head, len, map root, height, len, limit", 0x4356A84),
          ("state", 0x198, 0x8, "committed round", 0x44AC8CF),
          ("state", 0x1A0, 0x18, "tx map root, height, len", 0x44ABFC3),
          ("state", 0x1B8, 0x18, "block map root, height, len", 0x44AB9A0),
          ("state", 0x1D0, 0x18, "request throttle map root, height, len", 0x44B80D9),
          ("state", 0x4D0, 0x18, "outbox vector", 0x44ACED0),
          ("state", 0xAC8, 0xC, "event time, written at 0x44adfee and 0x44ae016", 0x44AB984),
          ("state", 0xAD4, 0xC, "block time of the last commit record", 0x44AD5B1),
          ("state", 0xAE0, 0xC, "wall time of the last commit record", 0x44AD5B8))
GATES = ((1, 0x44AB9BF, "block map root and length are both nonzero", "return", "no blocks"),
         (2, 0x44ABBA7, "tip = highest round in the block map, the last key in key order on a tie", "-", ""),
         (3, 0x44ABD8E, "child = block named by the tip QC hash", "request reason 0 for that hash", "tip parent missing"),
         (4, 0x44ABE5C, "start = block named by the child QC hash", "request reason 0 for that hash", "second parent missing"),
         (5, 0x44ABE9F, "child.round == saturating(start.round + 1)", "return, no prune", "rounds not consecutive"),
         (6, 0x44ABF56, "start.round above the committed round starts the walk", "skip the walk", ""),
         (7, 0x44AC0E9, "every tx hash of the walked block is in the tx map with a tag other than ...01", "request reason 1 for the walked block, partial walk dropped", "tx missing"),
         (8, 0x44AC2E3, "proof present when child.round == saturating(walked.round + 1)", "proof None word", ""),
         (9, 0x44AC670, "parent of the walked block is in the block map", "0x14385c0, request reason 2 for that hash, partial walk dropped", "ancestor missing"),
         (10, 0x44AC6D9, "keep walking while the parent round is above the committed round", "stop", ""),
         (11, 0x44AC8B4, "last round reached equals the committed round", "return, partial walk dropped, no prune", "walk passed the watermark"),
         (12, 0x44AC8CF, "committed round = start.round", "-", ""),
         (13, 0x44AC8D8, "at least one record", "prune only", "nothing to commit, pruned"),
         (14, 0x44AC909, "stats 0, 1, 2: blocks, txs, bytes, last two capped at i64 max", "-", ""),
         (15, 0x44ACA24, "log committed with block hashes and tx hashes, walk order", "-", ""),
         (16, 0x44ACAB7, "remove each tx, sample event time minus tx time, write tx byte to the seen map", "a second removal of one hash does nothing", ""),
         (17, 0x44ACF22, "records reversed, oldest first", "-", ""),
         (18, 0x489B76B, "drop txs with time + 20 s strictly below event time, any tag", "-", ""),
         (19, 0x489814E, "drop blocks with round strictly below the committed round, any branch", "-", ""),
         (20, 0x44AD5EB, "per record, sample block time and wall time gaps", "-", ""),
         (21, 0x47F5255, "push one tag 3 outbox row per record", "-", "committed"))
ASK_GATES = ((1, 0x44B80E3, "throttle key: tag byte 1, committed round, 32 byte hash"), (2, 0x44B81F7, "new key makes a row stamped with event time, stat 4, log Registering request"), (3, 0x44B8206, "reason byte goes into the row's set"),
             (4, 0x44B8211, "wait 1.0 s, the caller's xmm0 only when r8 is set; all three sites here clear r8"), (5, 0x44B8272, "event time at or after row time + wait, else answer 2"),
             (6, 0x44B8280, "sent flag clear, else answer 2"), (7, 0x44B830B, "set the sent flag, stat 5, log, return the key"))


def text_rip_sites(image, opcode, targets):
    start, data = image.text_bytes()
    found = []
    at = data.find(opcode)
    while at >= 0:
        rel = struct.unpack_from("<i", data, at + 2)[0]
        target = start + at + 6 + rel
        if target in targets:
            found.append((start + at, target))
        at = data.find(opcode, at + 1)
    return found


def scan_call_sites(image, target):
    """Every e8 or e9 rel32 inside .text that lands on target; one opcode byte plus a checked displacement."""
    start, data = image.text_bytes()
    sites = []
    for match in re.finditer(rb"[\xe8\xe9]", data):
        at = match.start()
        if at + 5 <= len(data) and start + at + 5 + struct.unpack_from("<i", data, at + 1)[0] == target:
            sites.append(start + at)
    return sites


def scan_triggers(image):
    sites = scan_call_sites(image, COMMIT)
    if sites != [row[0] for row in TRIGGERS]:
        raise EvidenceError("call sites differ: %s" % sites)
    if COMMIT in image.relative().values():
        raise EvidenceError("a relocation names the walk")
    return sites


def check_pins(image):
    for _, va, text, _ in PINS:
        want = bytes.fromhex(text)
        at = image.offset(va)
        if bytes(image.blob[at:at + len(want)]) != want:
            raise EvidenceError("pin differs at %#x" % va)
    return len(PINS)


def check_constants(image):
    rows = []
    for va, value, use in CONSTANTS:
        bits = struct.unpack_from("<Q", image.blob, image.offset(va))[0]
        if to_float(bits) != value:
            raise EvidenceError("constant differs at %#x" % va)
        rows.append((va, bits, value, use))
    return rows


def check_strings(image):
    for va, text in STRINGS:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(text)]) != text.encode():
            raise EvidenceError("string differs at %#x" % va)
    return STRINGS


def check_locations(image):
    relative = image.relative()
    rows = []
    for site, slot, use in LOCATIONS:
        path, line, column = image.location(slot, relative)
        rows.append(("%#x" % site, "%#x" % slot, path, line, column, use))
    for site, text, size, line, use in FILE_LINES:
        path = bytes(image.blob[image.offset(text):image.offset(text) + size]).decode()
        word = struct.unpack_from("<Q", image.blob, image.offset(site + 2))[0]
        if word != (line << 32 | 1):
            raise EvidenceError("line word differs at %#x" % site)
        rows.append(("%#x" % site, "%#x" % text, path[path.rindex("/node/") + 1:], line, "-", use))
    return rows


def edits_for(image, rows):
    edits = []
    for row in rows:
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
    return edits


def first_failure(harness, cases):
    for case in cases:
        try:
            got = harness.run(case)
            if same(got, spec_run(case)[1]):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error):
            return case
    return None


MUTANT_CAP = 40


def mutant_cases(cases):
    return [case for case in cases if not case.name.startswith("vector")] + [case for case in cases if case.name.startswith("vector")][:60]


def reach_table(image, cases):
    """For each case the rows it reaches and its step count, on the unedited image; cheap cases come first."""
    harness = Harness(image)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    rows = []
    for case in cases:
        harness.machine.seen = set()
        before = harness.machine.steps
        harness.run(case)
        rows.append((harness.machine.steps - before, len(rows), case, frozenset(harness.machine.seen)))
    rows.sort(key=lambda row: row[:2])
    return rows


def run_mutants(image, cases, rows):
    """Each edit runs only on cases that reach its row, at most MUTANT_CAP of them, cheapest first."""
    table = reach_table(image, cases)
    results = []
    for va, kind, patch in edits_for(image, rows):
        chosen = [row[2] for row in table if va in row[3]][:MUTANT_CAP]
        harness = Harness(image, patch)
        harness.machine.step_limit = MUTANT_STEP_LIMIT
        hit = first_failure(harness, chosen)
        host = image.fde(va)[0]
        if hit is not None:
            results.append((host, va, kind, "killed", hit.name))
        else:
            results.append((host, va, kind, "survived", survivor_reason(va, kind)))
    return results


def analyse(image, mutate=True, vectors=300):
    triggers = scan_triggers(image)
    pins = check_pins(image)
    constants = check_constants(image)
    strings = check_strings(image)
    locations = check_locations(image)
    harness = Harness(image)
    cases = named_cases() + vector_cases(vectors)
    rows = check_all(harness, cases)
    machine = harness.machine
    reached = collections.Counter()
    selected = []
    for va in sorted(machine.seen):
        row = machine.cache[va]
        host = image.fde(va)[0]
        if host in STATIC_FUNCTIONS:
            reached[host] += row.size
            selected.append(row)
    labels = collections.Counter(label for _, label, _ in rows)
    result = dict(triggers=triggers, pins=pins, constants=constants, strings=strings, locations=locations, cases=cases, rows=rows, reached=reached, vector_count=vectors, labels=labels)
    for _, _, _, _, label in GATES:
        if label and not any(name.startswith(label) for name in labels):
            raise EvidenceError("gate outcome never reached: %s" % label)
    if mutate:
        result["mutations"] = run_mutants(image, mutant_cases(cases), selected)
        unexplained = [row for row in result["mutations"] if row[4] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[1]), row[2]) for row in unexplained])
    return result


def render(result, image):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    labels = result["labels"]
    tsv("gates.tsv", ("order", "site", "rule", "otherwise", "outcome_label", "cases"), [(order, "%#x" % va, rule, other, label or "-", sum(count for name, count in labels.items() if name.startswith(label)) if label else "-") for order, va, rule, other, label in GATES])
    tsv("throttle.tsv", ("order", "site", "rule"), [(order, "%#x" % va, rule) for order, va, rule in ASK_GATES])
    tsv("functions.tsv", ("function", "end", "bytes", "reached_bytes", "role"), [("%#x" % start, "%#x" % image.exact_fde(start)[1], image.exact_fde(start)[1] - start, result["reached"][start], ROLES[start]) for start in STATIC_FUNCTIONS])
    tsv("stubs.tsv", ("target", "kind", "what"), [("%#x" % key, "direct call", text) for key, text in sorted(STUBS.items())] + [("%#x" % key, "data slot", text) for key, text in sorted(SLOT_STUBS.items())])
    tsv("triggers.tsv", ("site", "host", "context"), [("%#x" % site, "%#x" % host, text) for site, host, text in TRIGGERS])
    tsv("layouts.tsv", ("record", "offset", "size", "field", "site"), [(record, "%#x" % offset, "%#x" % size, field, "%#x" % site) for record, offset, size, field, site in LAYOUT])
    tsv("pins.tsv", ("group", "address", "bytes", "meaning"), [(group, "%#x" % va, text, meaning) for group, va, text, meaning in PINS])
    tsv("constants.tsv", ("address", "bits", "value", "use"), [("%#x" % va, "%#018x" % bits, repr(value), use) for va, bits, value, use in result["constants"]])
    tsv("strings.tsv", ("address", "text"), [("%#x" % va, text) for va, text in result["strings"]])
    tsv("locations.tsv", ("site", "data", "path", "line", "column", "use"), result["locations"])
    tsv("outcomes.tsv", ("outcome", "cases"), sorted(labels.items()))
    rows = []
    for case, label, got in result["rows"]:
        commits = [item[1] for item in got["out"] if item[0] == "commit"]
        asks = [item for item in got["out"] if item[0] == "ask"]
        rows.append((case.name, label, len(case.blocks), len(case.txs), case.watermark, got["watermark"], len(commits), sum(1 for item in commits if item["proof"]), len(asks), got["tx_count"], got["block_count"]))
    tsv("cases.tsv", ("case", "outcome", "blocks", "txs", "committed_before", "committed_after", "records", "records_with_proof", "requests", "txs_after", "blocks_after"), rows)
    if "mutations" in result:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"), [("%#x" % host, "%#x" % va, kind, outcome, detail) for host, va, kind, outcome, detail in result["mutations"]])
    summary = {"binary": "artifacts/node/94/hl-node", "sha256": SHA256, "cases": len(result["cases"]), "vector_cases": result["vector_count"], "named_cases": len(result["cases"]) - result["vector_count"], "functions_run": len(STATIC_FUNCTIONS),
               "reached_bytes": sum(result["reached"].values()), "function_bytes": sum(image.exact_fde(start)[1] - start for start in STATIC_FUNCTIONS), "pins": result["pins"], "call_sites": len(result["triggers"]), "gates": len(GATES), "mutant_cases": len(mutant_cases(result["cases"]))}
    if "mutations" in result:
        rows = result["mutations"]
        summary["mutations"] = {"total": len(rows), "killed": sum(1 for r in rows if r[3] == "killed"), "survived": sum(1 for r in rows if r[3] == "survived")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image), image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(files.items()):
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
