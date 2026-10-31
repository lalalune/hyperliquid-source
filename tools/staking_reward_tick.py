#!/usr/bin/env python3
"""Pin node #94 c_staking block tick: reward rate, staged rows, commission and delegator split, 1.5x lock bonus, stake snapshots, 1% decay.

0x3996730 is the tick host, 0x3373420 + 0x3be5630 stage rewards, 0x33709f0 pays them out, 0x37d9a10 and 0x37d9af0 store history
rows, 0x336f9f0 + 0x3c12170 decay the second stake word, 0x37d5e10 and 0x37d9cf0 pick the latest history row. The real bytes run
under recording stubs over real B-tree nodes, a separately written rule list predicts every run, and every reached conditional
row, immediate and field offset is mutated. No objdump or readelf output is parsed and the binary is never executed. Standard
library only.

    python3 tools/staking_reward_tick.py --out <dir>
"""

import argparse
import bisect
import hashlib
import json
import math
import multiprocessing
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
HEAP_SIZE = 0x80000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 400000
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
        self.hops = {}
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


def wrap32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


HOST = 0x3996730
STAGE = 0x3373420
TOTAL = 0x3C10D70
CLOSURE = 0x3BE5630
DIST = 0x33709F0
DECAY = 0x336F9F0
DECAY_CORE = 0x3C12170
SNAP = 0x37D9A10
JAIL_SNAP = 0x37D9AF0
EPOCH_KEY = 0x37D9CF0
STAKES_AT = 0x37D5E10
USER_ENTRY = 0x33BC0A0
STAGED_ENTRY = 0x33BC5F0
TARGETS = (HOST, STAGE, TOTAL, CLOSURE, DIST, DECAY, DECAY_CORE, SNAP, JAIL_SNAP, EPOCH_KEY, STAKES_AT, USER_ENTRY, STAGED_ENTRY)
NAMES = {HOST: "tick_host", STAGE: "stage_reward", TOTAL: "total_weight", CLOSURE: "stage_rows", DIST: "distribute", DECAY: "decay_wrapper", DECAY_CORE: "decay_core", SNAP: "stake_snapshot", JAIL_SNAP: "jail_snapshot",
         EPOCH_KEY: "latest_key", STAKES_AT: "latest_row", USER_ENTRY: "user_entry", STAGED_ENTRY: "staged_entry"}
SLOT_HOST = 0x5773A30
SLOT_COMPARE = 0x576E488
SLOT_COPY = 0x576DFE0
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_ALLOC_FAIL = 0x576DFB8
SLOT_NODE_FAIL = 0x576E020
SLOT_UNWRAP = 0x576E470
SLOT_ASSERT = 0x576E108
SLOT_POWER = 0x5775128
SLOT_RECORD = 0x5773190
SLOT_GROW = 0x57756A0
SLOT_SORT_LONG = 0x5775CB0
NOW = 0x4EE3800
ELAPSED = 0x4EE3730
RANGE = 0x2FE1490
ITER = 0x33B0800
SINK = 0x3990130
STATUS_HOOK = 0x3379490
DROPS = (0x33F0DA0, 0x33F32F0, 0x33F3A90)
SORT_SHORT = 0x33879D0
BULK = 0x2FBE050
USER_LEAF = 0x2F14BC0
STAGED_LEAF = 0x2F3F5D0
CLONE_SET = 0x33E31F0
CLONE_STAKES = 0x33EC760
JAIL_INSERT = 0x33A5C70
JAIL_POP = 0x33AE090
STAKE_INSERT = 0x33A2C20
STAKE_POP = 0x33ADEC0
MARK_BASE = 0x7700000000
ONCE_WORD = 0x577AB98
HOP_STAGE = (0x3373847, 0x3373BBD)
HOP_DECAY = (0x336FA2B, 0x336FE2F)
HOP_DIST = (0x3371EAB, 0x3372271)
STATIC_RATE_BASE = 0.015
YEAR_SECONDS = 31557600.0
FRACTION_TOP = 1.01
BPS = 0.0001
DECAY_KEEP = 0.99
WINDOW = 2000
BACK = 200
STATUS_RESERVE = 0xBE
TOP = MASK[8]
OUT = HEAP_BASE + 0x200
CTX = HEAP_BASE + 0x400
PAIR = HEAP_BASE + 0x500
GUARD = HEAP_BASE + 0x540
CLOSE = HEAP_BASE + 0x580
FLAG = HEAP_BASE + 0x5C0
STATE = HEAP_BASE + 0x1000
NODES = HEAP_BASE + 0x5000
ARENA = HEAP_BASE + 0x70000
USED = 0x7C000
FILL = 0xCC
S_SIZE = 0x300
S_HEAD = 0
S_STAKES = 0x10
S_INTERVAL = 0x28
S_LOW = 0x30
S_HIST = 0x38
S_CAP = 0x50
S_CUR = 0x58
S_RESERVE = 0x60
S_DECAY = 0xA0
S_JAIL_INTERVAL = 0xB0
S_JAIL_HIST = 0xC0
S_JAILED = 0xD8
S_JAIL_CAP = 0xF0
S_STAGE = 0x100
S_DIST = 0x110
S_PROFILES = 0x150
S_DELEGATORS = 0x180
S_STAGED = 0x1E0
S_USERS = 0x1F8
P_COMMISSION = 0x38
P_SIGNER = 0x40
MUTABLE = (0x48, 0x60, 0x68, 0xA8, 0xD0, 0x108, 0x118, 0x1E0, 0x1E8, 0x1F0, 0x1F8, 0x200, 0x208)


class Layout:
    def __init__(self, key_size, val_size, val_at, key_at, len_at, edge_at, parent_at, slot_at):
        self.key_size, self.val_size, self.val_at, self.key_at = key_size, val_size, val_at, key_at
        self.len_at, self.edge_at, self.parent_at, self.slot_at = len_at, edge_at, parent_at, slot_at
        self.size = edge_at + 12 * 8


ADDRESS_SET = Layout(20, 0, 0xE8, 8, 0xE6, 0xE8, 0, 0xE4)
AMOUNT_MAP = Layout(20, 8, 8, 0x60, 0x13E, 0x140, 0, 0x13C)
STAKE_MAP = Layout(20, 0x10, 0, 0xB8, 0x196, 0x198, 0xB0, 0x194)
PROFILE_MAP = Layout(20, 0x58, 0, 0x3D0, 0x4AE, 0x4B0, 0x3C8, 0x4AC)
USER_MAP = Layout(20, 0x18, 8, 0x110, 0x1EE, 0x1F0, 0, 0x1EC)
DELEGATOR_MAP = Layout(20, 0x20, 8, 0x168, 0x246, 0x248, 0, 0x244)
HISTORY = Layout(8, 0x28, 0x60, 8, 0x21A, 0x220, 0, 0x218)
JAIL_HISTORY = Layout(8, 0x18, 0x60, 8, 0x16A, 0x170, 0, 0x168)


def address_of(index):
    return bytes([0x20 + index]) + bytes((0xA0 + index + at * 5) & 0xFF for at in range(19))


def address_index(key):
    index = key[0] - 0x20
    if address_of(index) != key:
        raise Halt("address bytes")
    return index


def date_word(year, ordinal, flags=5):
    return (year << 13 | ordinal << 4 | flags) & MASK[4]


def signed32(value):
    return value - (1 << 32) if value >> 31 else value


def day_count(word):
    word = signed32(word)
    year, ordinal = word >> 13, (word >> 4) & 0x1FF
    y = year - 1
    return 365 * y + y // 4 - y // 100 + y // 400 + ordinal - 719163


def to_u64(value):
    """Rust `f64 as u64`: truncate, NaN is 0, both ends saturate."""
    if value != value or value <= 0:
        return 0
    if value >= 18446744073709551616.0:
        return TOP
    return int(value)


def cast_clamped(value):
    """Infinities and NaN give 0; finite values outside 0..2^64 clamp before the cast."""
    if value != value or value in (float("inf"), float("-inf")):
        return 0
    return to_u64(value)


def rate_of(seconds_value, total, supply):
    q = STATIC_RATE_BASE / max(math.sqrt(float(total) / float(supply)), STATIC_RATE_BASE)
    h = YEAR_SECONDS / seconds_value
    return (q * q * -0.5 + q) / h


def reward_rate(case, rows):
    if not case.a:
        return 0.0
    total = 0
    for _, _, weight in rows:
        total += weight
        if total > TOP:
            return 0.0
    if not case.b:
        return 0.0
    seconds_value = float(case.stage[0]) / 1000.0
    if not seconds_value > 0:
        raise Panic("assert_duration")
    return rate_of(seconds_value, total, case.b)


class Panic(Exception):
    pass


class Case:
    FIELDS = dict(
        now=(date_word(2026, 304), 3600, 5000000), round=10000, a=1, b=1000000000000, chain=1, direct=False,
        stage=(3600000, 0), dist=(3600000, 0), decay=(3600000, 0), interval=100000, jail_interval=100000, cap=10, jail_cap=10,
        stakes=((1, 400000000000, 410000000000), (2, 200000000000, 200000000000), (3, 100000000000, 90000000000)),
        hist=((9000, ((1, 400000000000, 410000000000), (2, 200000000000, 200000000000), (3, 100000000000, 90000000000))),), low=1000, cur=9000,
        head=(1, 0x4141414142424242), reserve=(1, 500000000000), profiles=((1, 11, 500), (2, 12, 1000), (3, 13, 0)), power=(11, 12, 13), jailed=(), jail_hist=((9000, ()),),
        staged=(), users=(), delegators=(),
    )

    def __init__(self, name, **fields):
        self.name = name
        unknown = set(fields) - set(self.FIELDS)
        if unknown:
            raise EvidenceError("unknown field %s" % sorted(unknown))
        for key, value in self.FIELDS.items():
            setattr(self, key, fields.get(key, value))


def latest(rows, low, current):
    """Key of the last row at or past the window start, or None."""
    keys = sorted(row[0] for row in rows)
    if not keys:
        return None
    high = min(low + WINDOW, TOP)
    start = low if current < high else max((current - BACK) & TOP, low)
    if keys[-1] < start:
        return None
    return keys[-1]


class Spec:
    def __init__(self, case):
        self.case = case
        c = case
        self.reserve = list(c.reserve)
        self.staged = dict(c.staged)
        self.users = {index: list(row) for index, *row in c.users}
        self.stakes = [list(row) for row in c.stakes]
        self.hist = {key: list(rows) for key, rows in c.hist}
        self.jail = {key: tuple(sorted(rows)) for key, rows in c.jail_hist}
        self.popped = 0
        self.jail_popped = 0
        self.dropped = 0
        self.records = []
        self.status = []
        self.last = dict(stage=c.stage[1], dist=c.dist[1], decay=c.decay[1])
        self.sink = None
        self.stage_rows = None

    def add(self, left, right):
        if left + right > TOP:
            self.records.append("add")
            return TOP
        return left + right

    def sub(self, left, right):
        if right > left:
            self.records.append("sub")
            return 0
        return left - right

    def millis(self):
        date, seconds_value, nanos = self.case.now
        value = (day_count(date) * 86400 + seconds_value) * 1000 + nanos // 1000000
        return max(value, 0)

    def fired(self, name, bucket):
        now = self.millis() // bucket
        hit = now > self.last[name]
        self.last[name] = max(self.last[name], now)
        return hit

    def user(self, index):
        return self.users.setdefault(index, [0, 0, 0, 0])

    def stage(self):
        c = self.case
        key = latest(c.hist, c.low, c.cur)
        if key is None:
            return None
        rows = self.hist[key]
        rate = reward_rate(c, rows)
        profiles = {index: (signer, commission) for index, signer, commission in c.profiles}
        out = []
        for index, stake, _ in sorted(rows):
            profile = profiles.get(index)
            if profile is None or profile[0] not in c.power or profile[0] in c.jailed:
                out.append((index, None))
                continue
            amount = 0
            if 0 <= rate <= FRACTION_TOP:
                amount = cast_clamped(rate * float(stake))
            if amount and self.reserve[0] == 1:
                left = self.sub(self.reserve[1], amount)
                taken = self.reserve[1] - left
                self.reserve[1] = left
                self.staged[index] = self.add(self.staged.get(index, 0), taken)
            out.append((index, amount))
        return out

    def distribute(self):
        c = self.case
        key = latest(c.hist, c.low, c.cur)
        if key is None:
            self.staged = {}
            return None
        if self.reserve[0] & 0xFF == 0:
            return None
        pending = sorted(self.staged.items())
        self.staged = {}
        profiles = {index: commission for index, _, commission in c.profiles}
        delegators = dict(c.delegators)
        rows = []
        kept = 0
        for validator, amount in pending:
            left = amount
            if validator in profiles:
                fraction = float(profiles[validator]) * BPS
                commission = cast_clamped(fraction * float(amount)) if fraction <= FRACTION_TOP else 0
                share = self.sub(amount, commission)
                row = self.user(validator)
                row[0] = self.add(row[0], amount - share)
                if commission:
                    rows.append((commission, validator, validator, 0))
                left = share
                if validator in delegators:
                    left = self.split(validator, share, delegators[validator], key, rows)
            kept = self.add(kept, left)
        if self.reserve[0] & MASK[4] != 1:
            self.reserve = [1, kept]
        elif self.reserve[1] + kept > TOP:
            self.status.append(STATUS_RESERVE)
        else:
            self.reserve[1] += kept
        self.sink = rows
        return rows

    def split(self, validator, share, members, key, rows):
        weights = [(index, current if epoch == key else previous) for index, previous, current, epoch in members]
        total = 0
        for _, weight in weights:
            total += weight
            if total > TOP:
                return share
        if not total:
            return share
        left = share
        wide = float(share)
        for index, weight in weights:
            part = float(weight) / float(total)
            reward = cast_clamped(part * wide) if 0 <= part <= FRACTION_TOP else 0
            rest = self.sub(left, reward)
            row = self.user(index)
            row[0] = self.add(row[0], left - rest)
            left = rest
            whole = reward
            date, seconds_value, nanos = self.case.now
            if row[1] and (signed32(date), seconds_value, nanos) < (signed32(row[1]), row[2], row[3]):
                half = reward >> 1
                remain = self.sub(self.reserve[1], half)
                taken = self.reserve[1] - remain
                self.reserve[1] = remain
                row[0] = self.add(row[0], taken)
                whole = self.add(half, reward)
            else:
                row[1] = 0
            if whole:
                rows.append((whole, index, validator, 1))
        return left

    def snapshots(self):
        c = self.case
        if not self.jail or self.deadline(c.jail_interval, self.jail) <= c.round:
            self.dropped += c.round in self.jail
            self.jail[c.round] = tuple(sorted(c.jailed))
            while len(self.jail) - self.jail_popped > c.jail_cap:
                self.jail_popped += 1
                self.dropped += 1
        if not self.hist or self.deadline(c.interval, self.hist) <= c.round:
            self.dropped += c.round in self.hist
            self.hist[c.round] = [tuple(row) for row in self.stakes]
            while len(self.hist) - self.popped > c.cap:
                self.popped += 1
                self.dropped += 1

    def deadline(self, interval, rows):
        return min(interval + max(rows), TOP)

    def decay(self):
        for row in self.stakes:
            row[1] = row[1] + to_u64(float(row[2] - row[1]) * DECAY_KEEP) if row[2] >= row[1] else row[2]

    def run(self):
        c = self.case
        if self.fired("stage", c.stage[0]):
            self.stage_rows = self.stage()
        dist = self.distribute() if self.fired("dist", c.dist[0]) else None
        self.snapshots()
        if self.fired("decay", c.decay[0]):
            self.decay()
        hist = [(key, tuple(tuple(row) for row in sorted(self.hist[key]))) for key in sorted(self.hist)][self.popped:]
        jail = sorted(self.jail)[self.jail_popped:]
        state = (tuple(self.last[k] for k in ("stage", "dist", "decay")), tuple(self.reserve), tuple(sorted(self.staged.items())),
                 tuple((index,) + tuple(row[:1]) + ((row[1], row[2], row[3]) if row[1] else (0, 0, 0)) for index, row in sorted(self.users.items())),
                 tuple(tuple(row) for row in self.stakes), tuple((key, rows) for key, rows in hist), tuple((key, self.jail[key]) for key in jail))
        stage = None if self.stage_rows is None else tuple(self.stage_rows)
        sink = None if dist is None else tuple(dist)
        return ("done", stage, sink, tuple(self.status), tuple(self.records), state, self.dropped)


def spec_run(case, frozen):
    try:
        if case.direct:
            reward_rate(case, [(0, 0, 1)])
            return ("done",)
        return Spec(case).run() + (frozen,)
    except Panic as caught:
        return ("panic", str(caught))


def capacity(height):
    return 7 if height == 0 else 4 * capacity(height - 1) + 3


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(TARGETS)
        statics = machine.memory.statics
        hooks = {SLOT_COMPARE: self.on_compare, SLOT_COPY: self.on_copy, SLOT_ALLOC: self.on_alloc, SLOT_FREE: self.on_nothing, SLOT_ALLOC_FAIL: self.on_stop, SLOT_NODE_FAIL: self.on_stop, SLOT_UNWRAP: self.on_stop, SLOT_ASSERT: self.on_assert,
                 SLOT_POWER: self.on_power, SLOT_RECORD: self.on_record, SLOT_GROW: self.on_grow, SLOT_SORT_LONG: self.on_sort_long}
        for slot, hook in hooks.items():
            marker = MARK_BASE + slot
            statics[slot] = marker
            machine.slots[marker] = hook
        statics[ONCE_WORD] = 0
        machine.calls = {NOW: self.on_now, ELAPSED: self.on_elapsed, RANGE: self.on_range, ITER: self.on_iter, SINK: self.on_sink, STATUS_HOOK: self.on_status, SORT_SHORT: self.on_sort, BULK: self.on_bulk, USER_LEAF: self.on_user_leaf,
                         STAGED_LEAF: self.on_staged_leaf, CLONE_SET: self.on_clone_set, CLONE_STAKES: self.on_clone_stakes, JAIL_INSERT: self.on_jail_insert, JAIL_POP: self.on_jail_pop, STAKE_INSERT: self.on_stake_insert, STAKE_POP: self.on_stake_pop}
        machine.calls[DROPS[0]] = self.on_nothing
        machine.calls[DROPS[1]] = machine.calls[DROPS[2]] = self.on_drop
        machine.hops = {HOP_STAGE[0]: self.hop_stage, HOP_DECAY[0]: self.hop_decay, HOP_DIST[0]: self.hop_dist}
        self.case = None
        self.frozen_digest = None

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def bytes_at(self, addr, size):
        return self.machine.memory.bytes_at(addr, size)

    def word(self, at, value, size=8):
        self.machine.memory.write(at, size, value & MASK[8])

    def read(self, at, size=8):
        return self.machine.memory.read(at, size)

    def hop_stage(self, machine):
        return HOP_STAGE[1]

    def hop_decay(self, machine):
        return HOP_DECAY[1]

    def hop_dist(self, machine):
        machine.regs[RBX] = self.read(machine.regs[RSP] + 0xE0)
        return HOP_DIST[1]

    def on_nothing(self, machine):
        pass

    def on_drop(self, machine):
        self.dropped += 1

    def on_stop(self, machine):
        raise Panicked("unwrap")

    def on_assert(self, machine):
        self.expect(machine.regs[RSI] == 0x1E and self.bytes_at(machine.regs[RDI], 0x1E) == b"assertion failed: other.0 > 0.", "assert text")
        raise Panicked("assert_duration")

    def on_compare(self, machine):
        regs = machine.regs
        size = regs[RDX]
        self.expect(size <= 0x200, "compare length")
        left, right = self.bytes_at(regs[RDI], size), self.bytes_at(regs[RSI], size)
        result = 0 if left == right else 0x1234 if left > right else -0x1234
        regs[RAX] = (0x5A5A5A5A << 32) | result & MASK[4]

    def on_copy(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] <= 0x400, "copy length")
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def allocate(self, size):
        at = self.arena
        self.arena += (size + 15) & ~15
        self.expect(self.arena < HEAP_BASE + USED, "arena")
        self.machine.memory.put_bytes(at, bytes([FILL]) * size)
        return at

    def on_alloc(self, machine):
        machine.regs[RAX] = self.allocate(machine.regs[RDI])

    def on_now(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == 1, "clock id")
        machine.regs[RAX] = 1
        machine.regs[RDX] = 2
        machine.keep_rdx = True

    def on_elapsed(self, machine):
        self.word(machine.regs[RDI], 1, 1)

    def on_power(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] & 0xFF == self.case.chain and regs[RCX] == STATE, "power arguments")
        self.expect(regs[RSI] in self.snapshot_values, "power row")
        self.stage_rows = ()
        self.holder(regs[RDI], AMOUNT_MAP, [(address_of(index), struct.pack("<Q", 7)) for index in sorted(self.case.power)])

    def on_record(self, machine):
        location = machine.regs[RSI]
        self.expect(machine.regs[RDI] & MASK[4] == 0, "recorder direction")
        self.records.append({0x56DFD90: "sub", 0x56DFD78: "add"}.get(location, "other"))

    def on_status(self, machine):
        self.status.append(self.read(machine.regs[RDI], 2))

    def on_grow(self, machine):
        vector = machine.regs[RDI]
        cap, ptr, count = self.read(vector), self.read(vector + 8), self.read(vector + 0x10)
        self.expect(count == cap, "grow only when full")
        new = max(4, cap * 2)
        at = self.allocate(new * 0x38)
        if count:
            machine.memory.copy(at, ptr, count * 0x38)
        self.word(vector, new)
        self.word(vector + 8, at)

    def sort_rows(self, base, count):
        rows = [self.bytes_at(base + 0x28 * at, 0x28) for at in range(count)]
        rows.sort(key=lambda row: row[:20])
        for at, row in enumerate(rows):
            self.machine.memory.put_bytes(base + 0x28 * at, row)

    def on_sort(self, machine):
        self.sort_rows(machine.regs[RDI], machine.regs[RSI])

    def on_sort_long(self, machine):
        self.sort_rows(machine.regs[RDI], machine.regs[RSI])

    def on_bulk(self, machine):
        regs = machine.regs
        it = regs[RSI]
        at, end = self.read(it + 8), self.read(it + 0x18)
        rows = []
        while at != end:
            key = self.bytes_at(at, 20)
            flag = self.read(at + 0x18)
            rows.append((address_index(key), self.read(at + 0x20) if flag else None))
            self.expect(flag in (0, 1), "row flag")
            at += 0x28
        self.stage_rows = tuple(rows)
        self.word(regs[RDX], len(rows))

    def on_sink(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] & 0xFF == self.case.chain and regs[RCX] == CTX and regs[RSI] == STATE, "sink arguments")
        vector = regs[R8]
        ptr, count = self.read(vector + 8), self.read(vector + 0x10)
        rows = []
        for at in range(count):
            base = ptr + 0x38 * at
            rows.append((self.read(base), address_index(self.bytes_at(base + 8, 20)), address_index(self.bytes_at(base + 0x1C, 20)), self.read(base + 0x30, 1)))
        self.sink_rows = tuple(rows)
        for at in range(3):
            self.word(regs[RDI] + 8 * at, 0x7777000 + at)

    def walk(self, layout, root, height):
        """In-order (node, index) pairs of a real tree."""
        found = []
        if not root:
            return found
        count = self.read(root + layout.len_at, 2)
        self.expect(count <= 11, "node length")
        for at in range(count):
            if height:
                found.extend(self.walk(layout, self.read(root + layout.edge_at + 8 * at), height - 1))
            found.append((root, at))
        if height:
            found.extend(self.walk(layout, self.read(root + layout.edge_at + 8 * count), height - 1))
        return found

    def on_iter(self, machine):
        regs = machine.regs
        if self.drain is None:
            it = regs[RSI]
            root, height, count = self.read(it + 0x10), self.read(it + 0x18), self.read(it + 0x40)
            self.expect(self.read(it) == 0 or self.stage_rows is not None or root == self.staged_root, "drain root")
            self.drain = self.walk(AMOUNT_MAP, root, height) if self.read(it) else []
            self.expect(len(self.drain) == count or not self.drain, "drain length")
        out = regs[RDI]
        if self.drain:
            node, index = self.drain.pop(0)
            self.word(out, node)
            self.word(out + 8, 0)
            self.word(out + 0x10, index)
        else:
            self.word(out, 0)

    def on_range(self, machine):
        regs = machine.regs
        out, root, height, start = regs[RDI], regs[RSI], regs[RDX], regs[RCX]
        places = self.walk(HISTORY, root, height)
        node = root
        for _ in range(height):
            node = self.read(node + HISTORY.edge_at + 8 * self.read(node + HISTORY.len_at, 2))
        tail = self.read(node + HISTORY.len_at, 2)
        hit = next(((n, i) for n, i in places if self.read(n + HISTORY.key_at + 8 * i) >= start), None)
        front = hit if hit else (node, tail)
        self.word(out, front[0])
        self.word(out + 8, 0)
        self.word(out + 0x10, front[1])
        self.word(out + 0x18, node)
        self.word(out + 0x20, 0)
        self.word(out + 0x28, tail)

    def on_user_leaf(self, machine):
        regs = machine.regs
        handle = regs[RSI]
        node, height, index = self.read(handle), self.read(handle + 8), self.read(handle + 0x10)
        self.expect(height == 0, "leaf handle")
        self.insert_row(USER_MAP, node, index, self.bytes_at(regs[RDX], 20), self.bytes_at(regs[RCX], 0x18))
        self.word(regs[RDI], node)
        self.word(regs[RDI] + 8, 0)
        self.word(regs[RDI] + 0x10, index)

    def on_staged_leaf(self, machine):
        regs = machine.regs
        handle = regs[RSI]
        node, height, index = self.read(handle), self.read(handle + 8), self.read(handle + 0x10)
        self.expect(height == 0 and regs[RCX] & MASK[8] == 0, "leaf handle")
        self.insert_row(AMOUNT_MAP, node, index, self.bytes_at(regs[RDX], 20), bytes(8))
        self.word(regs[RDI], node)
        self.word(regs[RDI] + 8, 0)
        self.word(regs[RDI] + 0x10, index)

    def on_clone_set(self, machine):
        regs = machine.regs
        rows = [(self.bytes_at(n + 8 + 20 * i, 20), b"") for n, i in self.walk(ADDRESS_SET, regs[RSI], regs[RDX])]
        self.holder(regs[RDI], ADDRESS_SET, rows)

    def on_clone_stakes(self, machine):
        regs = machine.regs
        layout = STAKE_MAP
        rows = [(self.bytes_at(n + layout.key_at + 20 * i, 20), self.bytes_at(n + 0x10 * i, 0x10)) for n, i in self.walk(layout, regs[RSI], regs[RDX])]
        self.holder(regs[RDI], layout, rows)

    def history_insert(self, holder, layout, key, value):
        root, height = self.read(holder), self.read(holder + 8)
        for n, i in self.walk(layout, root, height):
            if self.read(n + layout.key_at + 8 * i) == key:
                self.machine.memory.put_bytes(n + layout.val_at + layout.val_size * i, value)
                return True
        if not root:
            root = self.node(layout, (), ())
            self.word(holder, root)
            self.word(holder + 8, 0)
            self.word(holder + 0x10, 0)
            height = 0
        node = root
        for _ in range(height):
            node = self.read(node + layout.edge_at + 8 * self.read(node + layout.len_at, 2))
        self.insert_row(layout, node, self.read(node + layout.len_at, 2), struct.pack("<Q", key), value)
        self.word(holder + 0x10, self.read(holder + 0x10) + 1)
        return False

    def on_jail_insert(self, machine):
        regs = machine.regs
        had = self.history_insert(regs[RSI], JAIL_HISTORY, regs[RDX], self.bytes_at(regs[RCX], 0x18))
        self.word(regs[RDI], 1 if had else 0)

    def on_stake_insert(self, machine):
        regs = machine.regs
        had = self.history_insert(regs[RSI], HISTORY, regs[RDX], self.bytes_at(regs[RCX], 0x28))
        self.word(regs[RDI], 1 if had else 2)

    def on_jail_pop(self, machine):
        regs = machine.regs
        self.jail_popped += 1
        self.word(regs[RSI] + 0x10, self.read(regs[RSI] + 0x10) - 1)
        self.word(regs[RDI], 1)

    def on_stake_pop(self, machine):
        regs = machine.regs
        self.popped += 1
        self.word(regs[RSI] + 0x10, self.read(regs[RSI] + 0x10) - 1)
        self.word(regs[RDI] + 8, 0)

    def insert_row(self, layout, node, index, key, value):
        count = self.read(node + layout.len_at, 2)
        self.expect(count < 11 and index <= count, "leaf room")
        memory = self.machine.memory
        for at in range(count, index, -1):
            memory.put_bytes(node + layout.key_at + layout.key_size * at, self.bytes_at(node + layout.key_at + layout.key_size * (at - 1), layout.key_size))
            memory.put_bytes(node + layout.val_at + layout.val_size * at, self.bytes_at(node + layout.val_at + layout.val_size * (at - 1), layout.val_size))
        memory.put_bytes(node + layout.key_at + layout.key_size * index, key)
        memory.put_bytes(node + layout.val_at + layout.val_size * index, value)
        self.word(node + layout.len_at, count + 1, 2)

    def node(self, layout, items, children):
        base = self.next_node
        self.next_node += layout.size + 0x10
        self.expect(self.next_node < ARENA, "node area")
        memory = self.machine.memory
        memory.put_bytes(base, bytes([FILL]) * (layout.size + 0x10))
        for at, (key, value) in enumerate(items):
            if layout.key_size:
                memory.put_bytes(base + layout.key_at + layout.key_size * at, key)
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, value)
        for at in range(len(items), 11):
            if layout.val_size:
                memory.put_bytes(base + layout.val_at + layout.val_size * at, b"\xFF" * layout.val_size)
            if layout.key_size == 20:
                memory.put_bytes(base + layout.key_at + 20 * at, bytes(20))
        self.word(base + layout.len_at, len(items), 2)
        self.word(base + layout.parent_at, 0)
        for slot, child in enumerate(children):
            self.word(base + layout.edge_at + 8 * slot, child)
            self.word(child + layout.parent_at, base)
            self.word(child + layout.slot_at, slot, 2)
        return base

    def build(self, layout, items, height):
        if height == 0:
            return self.node(layout, items, ())
        size = len(items)
        low = (size - 3) // 4
        extra = (size - 3) - low * 4
        children, separators, at = [], [], 0
        for part in range(4):
            take = low + (1 if part < extra else 0)
            children.append(self.build(layout, items[at:at + take], height - 1))
            at += take
            if part < 3:
                separators.append(items[at])
                at += 1
        return self.node(layout, separators, children)

    def tree(self, layout, items):
        height = 0
        while capacity(height) < len(items):
            height += 1
        return self.build(layout, list(items), height), height

    def holder(self, at, layout, items):
        if not items:
            self.word(at, 0)
            self.word(at + 8, 0xB1B1)
            self.word(at + 0x10, 0)
            return
        root, height = self.tree(layout, items)
        self.word(at, root)
        self.word(at + 8, height)
        self.word(at + 0x10, len(items))

    def stake_rows(self, rows):
        return [(address_of(index), struct.pack("<QQ", first, second)) for index, first, second in sorted(rows)]

    def frozen(self):
        data = bytearray(self.bytes_at(STATE, S_SIZE))
        for offset in MUTABLE:
            data[offset:offset + 8] = bytes(8)
        return hashlib.sha256(bytes(data)).hexdigest()

    def fresh(self, case):
        memory = self.machine.memory
        memory.reset(USED)
        memory.put_bytes(STATE, bytes([FILL]) * S_SIZE)
        self.next_node = NODES
        self.arena = ARENA
        self.case = case
        self.records = []
        self.status = []
        self.stage_rows = None
        self.sink_rows = None
        self.drain = None
        self.popped = self.jail_popped = 0
        self.dropped = 0
        s = STATE
        date, seconds_value, nanos = case.now
        self.word(CTX + 0x30, case.round)
        self.word(CTX + 0x60, date, 4)
        self.word(CTX + 0x64, seconds_value, 4)
        self.word(CTX + 0x68, nanos, 4)
        self.word(s + S_HEAD, case.head[0])
        self.word(s + S_HEAD + 8, case.head[1])
        self.holder(s + S_STAKES, STAKE_MAP, self.stake_rows(case.stakes))
        self.word(s + S_INTERVAL, case.interval)
        self.word(s + S_LOW, case.low)
        items = []
        self.snapshot_values = set()
        for key, rows in sorted(case.hist):
            root, height = self.tree(STAKE_MAP, self.stake_rows(rows)) if rows else (0, 0xB1B1)
            items.append((struct.pack("<Q", key), struct.pack("<QQQQQ", case.head[0], case.head[1], root, height, len(rows))))
        self.holder(s + S_HIST, HISTORY, items)
        for n, i in self.walk(HISTORY, self.read(s + S_HIST), self.read(s + S_HIST + 8)):
            self.snapshot_values.add(n + HISTORY.val_at + 0x28 * i)
        self.word(s + S_CAP, case.cap)
        self.word(s + S_CUR, case.cur)
        self.word(s + S_RESERVE, case.reserve[0])
        self.word(s + S_RESERVE + 8, case.reserve[1])
        for at, pair in ((S_DECAY, case.decay), (S_STAGE, case.stage), (S_DIST, case.dist)):
            self.word(s + at, pair[0])
            self.word(s + at + 8, pair[1])
        self.word(s + S_JAIL_INTERVAL, case.jail_interval)
        self.word(s + S_JAIL_CAP, case.jail_cap)
        jail = []
        for key, members in sorted(case.jail_hist):
            at = self.next_node
            self.next_node += 0x20
            self.holder(at, ADDRESS_SET, [(address_of(index), b"") for index in sorted(members)])
            jail.append((struct.pack("<Q", key), self.bytes_at(at, 0x18)))
        self.holder(s + S_JAIL_HIST, JAIL_HISTORY, jail)
        self.holder(s + S_JAILED, ADDRESS_SET, [(address_of(index), b"") for index in sorted(case.jailed)])
        profiles = []
        for index, signer, commission in sorted(case.profiles):
            value = bytearray(bytes([0xF0]) * 0x58)
            value[P_COMMISSION:P_COMMISSION + 8] = struct.pack("<Q", commission)
            value[P_SIGNER:P_SIGNER + 20] = address_of(signer)
            profiles.append((address_of(index), bytes(value)))
        self.holder(s + S_PROFILES, PROFILE_MAP, profiles)
        members = []
        for validator, rows in sorted(case.delegators):
            at = self.next_node
            self.next_node += 0x20
            self.holder(at, USER_MAP, [(address_of(index), struct.pack("<QQQ", previous, current, epoch)) for index, previous, current, epoch in rows])
            members.append((address_of(validator), self.bytes_at(at, 0x18) + bytes(8)))
        self.holder(s + S_DELEGATORS, DELEGATOR_MAP, members)
        self.holder(s + S_STAGED, AMOUNT_MAP, [(address_of(index), struct.pack("<Q", amount)) for index, amount in sorted(case.staged)])
        self.staged_root = self.read(s + S_STAGED)
        self.holder(s + S_USERS, USER_MAP, [(address_of(index), struct.pack("<QIII", bal, date_value, sec, nano) + bytes([0xEE]) * 4) for index, bal, date_value, sec, nano in sorted(case.users)])
        self.word(PAIR, case.a)
        self.word(PAIR + 8, case.b)
        self.frozen_digest = self.frozen()

    def history_rows(self, skip):
        rows = []
        s = STATE
        places = self.walk(HISTORY, self.read(s + S_HIST), self.read(s + S_HIST + 8))
        places = sorted(places, key=lambda p: self.read(p[0] + HISTORY.key_at + 8 * p[1]))[skip:]
        for n, i in places:
            at = n + HISTORY.val_at + 0x28 * i
            root, height = self.read(at + 0x10), self.read(at + 0x18)
            inner = []
            for m, j in self.walk(STAKE_MAP, root, height):
                inner.append((address_index(self.bytes_at(m + STAKE_MAP.key_at + 20 * j, 20)), self.read(m + 0x10 * j), self.read(m + 0x10 * j + 8)))
            self.expect((self.read(at), self.read(at + 8)) == self.case.head and self.read(at + 0x20) == len(inner), "snapshot head")
            rows.append((self.read(n + HISTORY.key_at + 8 * i), tuple(inner)))
        return tuple(rows)

    def jail_rows(self, skip):
        s = STATE
        places = self.walk(JAIL_HISTORY, self.read(s + S_JAIL_HIST), self.read(s + S_JAIL_HIST + 8))
        places = sorted(places, key=lambda p: self.read(p[0] + JAIL_HISTORY.key_at + 8 * p[1]))[skip:]
        rows = []
        for n, i in places:
            at = n + JAIL_HISTORY.val_at + 0x18 * i
            members = tuple(sorted(address_index(self.bytes_at(m + 8 + 20 * j, 20)) for m, j in self.walk(ADDRESS_SET, self.read(at), self.read(at + 8))))
            self.expect(self.read(at + 0x10) == len(members), "jail row length")
            rows.append((self.read(n + JAIL_HISTORY.key_at + 8 * i), members))
        return tuple(rows)

    def state(self):
        s = STATE
        memory = self.machine.memory
        lasts = (self.read(s + S_STAGE + 8), self.read(s + S_DIST + 8), self.read(s + S_DECAY + 8))
        reserve = (self.read(s + S_RESERVE), self.read(s + S_RESERVE + 8))
        staged = []
        for n, i in self.walk(AMOUNT_MAP, self.read(s + S_STAGED), self.read(s + S_STAGED + 8)) if self.read(s + S_STAGED) else ():
            staged.append((address_index(self.bytes_at(n + 0x60 + 20 * i, 20)), self.read(n + 8 + 8 * i)))
        self.expect(self.read(s + S_STAGED + 0x10) == len(staged), "staged length")
        users = []
        for n, i in self.walk(USER_MAP, self.read(s + S_USERS), self.read(s + S_USERS + 8)):
            at = n + 8 + 0x18 * i
            date = self.read(at + 8, 4)
            users.append((address_index(self.bytes_at(n + 0x110 + 20 * i, 20)), self.read(at), date, self.read(at + 0xC, 4) if date else 0, self.read(at + 0x10, 4) if date else 0))
        self.expect(self.read(s + S_USERS + 0x10) == len(users), "user length")
        stakes = []
        for n, i in self.walk(STAKE_MAP, self.read(s + S_STAKES), self.read(s + S_STAKES + 8)):
            stakes.append((address_index(self.bytes_at(n + STAKE_MAP.key_at + 20 * i, 20)), self.read(n + 0x10 * i), self.read(n + 0x10 * i + 8)))
        self.expect(self.read(s + S_HIST + 0x10) == len(self.walk(HISTORY, self.read(s + S_HIST), self.read(s + S_HIST + 8))) - self.popped, "history length")
        return (lasts, reserve, tuple(staged), tuple(users), tuple(stakes), self.history_rows(self.popped), self.jail_rows(self.jail_popped))

    def run(self, case):
        self.fresh(case)
        machine = self.machine
        if case.direct:
            self.word(GUARD + 0x20, 1, 1)
            self.word(CLOSE, STATE)
            self.word(CLOSE + 8, PAIR)
            self.word(CLOSE + 0x10, FLAG)
            self.word(FLAG, case.chain, 1)
            try:
                machine.run(STAGE, {RDI: OUT, RSI: GUARD, RDX: CLOSE})
            except Panicked as caught:
                return ("panic", str(caught))
            return ("done",)
        try:
            machine.run(HOST, {RDI: OUT, RSI: STATE, RDX: case.chain, RCX: CTX, R8: case.a, R9: case.b})
        except Panicked as caught:
            return ("panic", str(caught))
        stage_tag, dist_tag = self.read(OUT), self.read(OUT + 0x20)
        self.expect(stage_tag == (1 if self.stage_rows is not None else 0), "stage tag")
        self.expect(dist_tag == (1 if self.sink_rows is not None else 0), "distribute tag")
        if self.stage_rows is not None:
            self.expect(self.read(OUT + 0x18) == len(self.stage_rows), "stage map length")
        if self.sink_rows is not None:
            self.expect([self.read(OUT + 0x28 + 8 * at) for at in range(3)] == [0x7777000 + at for at in range(3)], "sink triple")
        self.expect(not self.drain, "drain finished")
        state = self.state()
        return ("done", self.stage_rows, self.sink_rows, tuple(self.status), tuple(self.records), state, self.dropped, self.frozen_digest)


H = 3600000
BIG = 1 << 63


def named_cases():
    out = []

    def add(name, **fields):
        out.append(Case(name, **fields))

    idle = dict(stage=(H, 1 << 40), dist=(H, 1 << 40), decay=(H, 1 << 40))
    add("idle")
    add("idle_all_buckets_past", **idle)
    add("stage_only", dist=idle["dist"], decay=idle["decay"])
    add("dist_only", stage=idle["stage"], decay=idle["decay"], staged=((1, 1000),))
    add("decay_only", stage=idle["stage"], dist=idle["dist"])
    bucket = Spec(Case("b")).millis() // H
    add("stage_bucket_equal", stage=(H, bucket), **{k: idle[k] for k in ("dist", "decay")})
    add("stage_bucket_next", stage=(H, bucket - 1), **{k: idle[k] for k in ("dist", "decay")})
    add("dist_bucket_equal", dist=(H, bucket), stage=idle["stage"], decay=idle["decay"], staged=((1, 500),))
    add("dist_bucket_next", dist=(H, bucket - 1), stage=idle["stage"], decay=idle["decay"], staged=((1, 500),))
    add("decay_bucket_equal", decay=(H, bucket), stage=idle["stage"], dist=idle["dist"])
    add("decay_bucket_next", decay=(H, bucket - 1), stage=idle["stage"], dist=idle["dist"])
    for name, now in (("year_0", (date_word(0, 1), 0, 0)), ("year_neg1", (date_word(-1, 200), 86399, 999999999)), ("year_neg401", (date_word(-401, 366), 1, 1)), ("year_1", (date_word(1, 1), 1, 0)), ("year_1969", (date_word(1969, 365), 86399, 0)),
                      ("epoch", (date_word(1970, 1), 0, 0)), ("epoch_one_ms", (date_word(1970, 1), 0, 1000000)), ("nanos_under_ms", (date_word(1970, 1), 0, 999999)), ("year_2400", (date_word(2400, 366), 86399, 999999999)),
                      ("year_9999", (date_word(9999, 365), 86399, 1000000)), ("year_262000", (date_word(262000, 200), 5, 7))):
        add("time_" + name, now=now, stage=(1, 0), dist=(7, 0), decay=(1000, 0))
    for name, size in (("low32", 0xFFFFFFFF), ("high33", 1 << 33), ("one", 1)):
        add("bucket_width_" + name, stage=(size, 0), dist=(size, 0), decay=(size, 0))
    add("millis_above_32_bits_small_width", stage=(3, 0), dist=(5, 0), decay=(9, 0))
    # stage rate
    for name, total, supply in (("full", 1000, 1000), ("half", 500, 1000), ("tenth", 10 ** 11, 10 ** 12), ("floor", 1, 10 ** 12), ("floor_edge", 225, 1000000), ("under_floor", 224, 1000000), ("over_full", 3000, 1000)):
        add("rate_" + name, hist=((9000, ((1, 10 ** 15, total), (2, 7 * 10 ** 14, 0))),), stakes=(), b=supply, dist=idle["dist"], decay=idle["decay"], reserve=(1, 1 << 62))
    for width in (1000, 60000, H, 86400000, 604800000, 31557600000):
        add("rate_period_%d" % width, stage=(width, 0), dist=idle["dist"], decay=idle["decay"], reserve=(1, 1 << 62))
    add("rate_a_zero", a=0, dist=idle["dist"], decay=idle["decay"])
    add("rate_b_zero", b=0, dist=idle["dist"], decay=idle["decay"])
    add("rate_weight_overflow", hist=((9000, ((1, 1000, TOP), (2, 2000, 5))),), dist=idle["dist"], decay=idle["decay"])
    add("rate_weight_exact_top", hist=((9000, ((1, 10 ** 12, TOP - 5), (2, 2000, 5))),), dist=idle["dist"], decay=idle["decay"], reserve=(1, TOP))
    add("rate_weight_zero", hist=((9000, ((1, 10 ** 9, 0),)),), dist=idle["dist"], decay=idle["decay"], reserve=(1, TOP))
    add("rate_above_cap", stage=(64000000000, 0), hist=((9000, ((1, 10 ** 6, 1),)),), profiles=((1, 11, 0),), b=1 << 62, dist=idle["dist"], decay=idle["decay"])
    add("rate_just_under_cap", stage=(63000000000, 0), hist=((9000, ((1, 10 ** 6, 1),)),), profiles=((1, 11, 0),), b=1 << 62, dist=idle["dist"], decay=idle["decay"], reserve=(1, 1 << 40))
    many = tuple((k, 1000 + k, 500 + k) for k in range(1, 9))
    add("stage_tall_tree", hist=((9000, many),), profiles=tuple((k, 100 + k, 100) for k in range(1, 9)), power=tuple(100 + k for k in range(1, 9)), dist=idle["dist"], decay=idle["decay"], reserve=(1, 1 << 40), stage=(10 ** 11, 0))
    wide = tuple((k, 10 ** 9 + k, 500 + k) for k in range(1, 23))
    add("stage_two_levels", hist=((9000, wide),), profiles=tuple((k, 100 + k, 100) for k in range(1, 12)), power=tuple(100 + k for k in range(1, 12)), dist=idle["dist"], decay=idle["decay"], reserve=(1, 1 << 40), stage=(10 ** 10, 0))
    # stage row gates
    three = ((1, 400000000000, 410000000000), (2, 200000000000, 200000000000), (3, 100000000000, 90000000000))
    add("row_no_profile", profiles=((2, 12, 1000), (3, 13, 0)), dist=idle["dist"], decay=idle["decay"])
    add("row_no_profiles_at_all", profiles=(), dist=idle["dist"], decay=idle["decay"])
    add("row_signer_not_in_power", power=(11, 13), dist=idle["dist"], decay=idle["decay"])
    add("row_power_empty", power=(), dist=idle["dist"], decay=idle["decay"])
    add("row_jailed_signer", jailed=(12,), dist=idle["dist"], decay=idle["decay"])
    add("row_jailed_all", jailed=(11, 12, 13), dist=idle["dist"], decay=idle["decay"])
    add("row_jailed_other_only", jailed=(55,), dist=idle["dist"], decay=idle["decay"])
    add("row_jailed_key_above", jailed=(99,), dist=idle["dist"], decay=idle["decay"])
    add("row_jailed_key_below", jailed=(1,), dist=idle["dist"], decay=idle["decay"])
    add("row_tall_jail_set", jailed=tuple(range(50, 62)), dist=idle["dist"], decay=idle["decay"])
    add("row_tall_power", power=tuple(range(11, 26)), dist=idle["dist"], decay=idle["decay"])
    add("row_tall_profiles", profiles=tuple((k, 10 + k, 7) for k in range(1, 15)), dist=idle["dist"], decay=idle["decay"])
    add("row_chain_0", chain=0, dist=idle["dist"], decay=idle["decay"])
    add("row_chain_3", chain=3, dist=idle["dist"], decay=idle["decay"])
    add("row_zero_stake", hist=((9000, ((1, 0, 10 ** 12), (2, 5, 0))),), dist=idle["dist"], decay=idle["decay"])
    add("row_reserve_none", reserve=(0, 77), dist=idle["dist"], decay=idle["decay"])
    add("row_reserve_tag_2", reserve=(2, 77), dist=idle["dist"], decay=idle["decay"])
    add("row_reserve_short", reserve=(1, 3), dist=idle["dist"], decay=idle["decay"])
    add("row_reserve_zero", reserve=(1, 0), dist=idle["dist"], decay=idle["decay"])
    add("row_staged_existing", staged=((1, 9), (2, 11)), dist=idle["dist"], decay=idle["decay"])
    add("row_staged_overflow", staged=((1, TOP),), dist=idle["dist"], decay=idle["decay"], reserve=(1, TOP))
    add("row_staged_key_order", staged=((2, 1), (9, 3)), dist=idle["dist"], decay=idle["decay"])
    add("row_staged_above", staged=((0, 1),), dist=idle["dist"], decay=idle["decay"])
    add("row_staged_tall", staged=tuple((k, 1) for k in range(4, 13)), dist=idle["dist"], decay=idle["decay"])
    # latest snapshot
    add("hist_empty", hist=(), dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_empty_with_staged", hist=(), staged=((1, 50),), stage=idle["stage"], decay=idle["decay"], interval=1 << 40)
    add("hist_stale_cur", hist=((500, three),), cur=9000, low=100, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_stale_with_staged", hist=((500, three),), cur=9000, low=100, staged=((1, 50),), stage=idle["stage"], decay=idle["decay"], interval=1 << 40)
    add("hist_window_edge_keep", hist=((8800, three),), cur=9000, low=100, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_window_edge_drop", hist=((8799, three),), cur=9000, low=100, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_inside_first_2000", hist=((1200, three),), cur=3000, low=1001, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_at_2000_edge", hist=((1200, three),), cur=3001, low=1001, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_past_2000_edge", hist=((2800, three),), cur=3001, low=1001, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_low_clamps_start", hist=((1500, three),), cur=3600, low=1500, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_low_saturates", hist=((TOP - 5, three),), cur=TOP - 4, low=TOP - 10, dist=idle["dist"], decay=idle["decay"], interval=1 << 40, round=10)
    add("hist_low_saturates_below", hist=((TOP - 1900, three),), cur=TOP - 1, low=TOP - 1999, dist=idle["dist"], decay=idle["decay"], interval=1 << 40, round=10)
    add("hist_two_rows_uses_last", hist=((8000, ((1, 10 ** 12, 1),)), (9000, three)), dist=idle["dist"], decay=idle["decay"])
    add("hist_three_rows_stale_first", hist=((100, ((1, 3, 4),)), (8900, three), (8950, ((2, 10 ** 11, 10 ** 11),))), dist=idle["dist"], decay=idle["decay"])
    add("hist_nine_rows", hist=tuple((8000 + 10 * k, ((1, 10 ** 11 + k, 10 ** 11),)) for k in range(9)), cur=8100, dist=idle["dist"], decay=idle["decay"], cap=20)
    add("hist_empty_row", hist=((9000, ()),), dist=idle["dist"], decay=idle["decay"])
    # commission and delegators
    member = (((1, ((21, 700, 900, 9000), (22, 300, 100, 8000))),))
    split = dict(stage=idle["stage"], decay=idle["decay"], staged=((1, 100000),))
    add("dist_commission_only", **split)
    add("dist_with_members", delegators=member, **split)
    add("dist_epoch_row_selects", delegators=((1, ((21, 700, 900, 8999), (22, 300, 100, 9000))),), **split)
    add("dist_no_profile", profiles=((2, 12, 1000),), delegators=member, **split)
    add("dist_no_profiles", profiles=(), **split)
    add("dist_commission_zero", profiles=((1, 11, 0),), delegators=member, **split)
    add("dist_commission_all", profiles=((1, 11, 10000),), delegators=member, **split)
    add("dist_commission_above_all", profiles=((1, 11, 10099),), delegators=member, **split)
    add("dist_commission_edge", profiles=((1, 11, 10100),), delegators=member, **split)
    add("dist_commission_too_high", profiles=((1, 11, 10101),), delegators=member, **split)
    add("dist_commission_huge", profiles=((1, 11, TOP),), delegators=member, **split)
    add("dist_amount_above_2_53", profiles=((1, 11, 1),), stage=idle["stage"], decay=idle["decay"], staged=((1, (1 << 60) + 3),), delegators=member, reserve=(1, 0))
    add("dist_amount_top", profiles=((1, 11, 3333),), stage=idle["stage"], decay=idle["decay"], staged=((1, TOP),), delegators=member, reserve=(1, 0))
    add("dist_amount_top_full_rate", profiles=((1, 11, 10050),), stage=idle["stage"], decay=idle["decay"], staged=((1, TOP),), reserve=(1, 0))
    add("dist_amount_zero", delegators=member, stage=idle["stage"], decay=idle["decay"], staged=((1, 0),))
    add("dist_empty_staged", stage=idle["stage"], decay=idle["decay"])
    add("dist_members_sum_overflow", delegators=((1, ((21, 0, TOP, 9000), (22, 0, 5, 9000))),), **split)
    add("dist_members_sum_exact", delegators=((1, ((21, 0, TOP - 5, 9000), (22, 0, 5, 9000))),), **split)
    add("dist_members_zero_weight", delegators=((1, ((21, 5, 0, 9000),)),), **split)
    add("dist_members_empty", delegators=((1, ()),), **split)
    add("dist_member_rounding_dust", delegators=((1, ((21, 1, 1, 0), (22, 1, 1, 0), (23, 1, 1, 0))),), stage=idle["stage"], decay=idle["decay"], staged=((1, 10),), profiles=((1, 11, 0),))
    add("dist_float_above_remaining", delegators=((1, ((21, 1, 1, 0), (22, (1 << 60), 1, 0))),), stage=idle["stage"], decay=idle["decay"], staged=((1, (1 << 62) - 1),), profiles=((1, 11, 0),), reserve=(1, 0))
    add("dist_reward_rounds_past_left", delegators=((1, ((21, 3, 3, 0), (22, 3, 3, 0))),), stage=idle["stage"], decay=idle["decay"], staged=((1, (1 << 54) + 1),), profiles=((1, 11, 0),))
    tall = tuple((30 + k, 10 + k, 20 + k, 9000) for k in range(1, 26))
    add("dist_members_three_levels", delegators=((1, tall),), stage=idle["stage"], decay=idle["decay"], staged=((1, 1 << 40),), profiles=((1, 11, 200),), users=tuple((30 + k, 5, 0, 0, 0) for k in range(1, 26)) + ((1, 0, 0, 0, 0),))
    add("dist_two_validators", delegators=member + ((2, ((21, 1, 1, 0), (24, 3, 3, 0))),), stage=idle["stage"], decay=idle["decay"], staged=((1, 1000), (2, 2000), (3, 3000)))
    add("dist_validator_has_user_row", delegators=member, users=((1, 77, 0, 0, 0), (21, 5, 0, 0, 0)), **split)
    add("dist_user_overflow_commission", users=((1, TOP - 1, 0, 0, 0),), **split)
    add("dist_user_overflow_member", delegators=((1, ((21, 1, 1, 0),)),), users=((21, TOP - 1, 0, 0, 0),), **split)
    add("dist_tall_users", delegators=member, users=tuple((40 + k, k, 0, 0, 0) for k in range(1, 24)) + ((21, 3, 0, 0, 0), (22, 3, 0, 0, 0), (1, 4, 0, 0, 0)), **split)
    add("dist_tall_delegator_map", delegators=tuple((k, ((21, 1, 1, 0),)) for k in range(1, 12)), **split)
    add("dist_tall_staged", delegators=member, stage=idle["stage"], decay=idle["decay"], staged=tuple((k, 100 + k) for k in range(1, 10)), profiles=tuple((k, 10 + k, 20) for k in range(1, 15)), users=())
    add("dist_kept_overflow", profiles=(), stage=idle["stage"], decay=idle["decay"], staged=((1, TOP), (2, 5)), reserve=(1, 0))
    add("dist_reserve_overflow", profiles=(), stage=idle["stage"], decay=idle["decay"], staged=((1, 9),), reserve=(1, TOP))
    add("dist_reserve_exact_top", profiles=(), stage=idle["stage"], decay=idle["decay"], staged=((1, 9),), reserve=(1, TOP - 9))
    add("dist_reserve_none", stage=idle["stage"], decay=idle["decay"], staged=((1, 9),), reserve=(0, 4))
    add("dist_reserve_tag_2", stage=idle["stage"], decay=idle["decay"], staged=((1, 9),), reserve=(2, 4))
    add("dist_reserve_byte_0_high_bits", stage=idle["stage"], decay=idle["decay"], staged=((1, 9),), reserve=(0x100, 4))
    add("dist_and_stage_same_tick", delegators=member, staged=((2, 500),))
    # long term bonus
    now = Case.FIELDS["now"]
    later = now[0] + (2 << 4)
    locks = dict(delegators=((1, ((21, 500, 500, 0), (22, 500, 500, 0))),), profiles=((1, 11, 0),), **split)
    add("lock_future_date", users=((21, 1, later, 5, 6),), **locks)
    add("lock_past_date", users=((21, 1, now[0] - (2 << 4), 5, 6),), **locks)
    add("lock_equal_date_later_second", users=((21, 1, now[0], now[1] + 1, 0),), **locks)
    add("lock_equal_date_earlier_second", users=((21, 1, now[0], now[1] - 1, 0),), **locks)
    add("lock_equal_second_later_nano", users=((21, 1, now[0], now[1], now[2] + 1),), **locks)
    add("lock_equal_second_earlier_nano", users=((21, 1, now[0], now[1], now[2] - 1),), **locks)
    add("lock_exact_now", users=((21, 1, now[0], now[1], now[2]),), **locks)
    add("lock_none_word", users=((21, 1, 0, 9, 9),), **locks)
    add("lock_negative_date", users=((21, 1, date_word(-5, 10), 9, 9),), **locks)
    add("lock_now_negative_lock_positive", now=(date_word(-3, 10), 5, 5), users=((21, 1, date_word(2, 10), 9, 9),), **locks)
    add("lock_both_members", users=((21, 1, later, 0, 0), (22, 2, later, 1, 1)), **locks)
    add("lock_reserve_short", users=((21, 1, later, 0, 0),), reserve=(1, 3), **{k: v for k, v in locks.items()})
    add("lock_reserve_zero", users=((21, 1, later, 0, 0),), reserve=(1, 0), **locks)
    add("lock_odd_reward", users=((21, 1, later, 0, 0),), delegators=((1, ((21, 1, 1, 0),)),), profiles=((1, 11, 0),), stage=idle["stage"], decay=idle["decay"], staged=((1, 1001),))
    add("lock_reward_one", users=((21, 1, later, 0, 0),), delegators=((1, ((21, 1, 1, 0),)),), profiles=((1, 11, 0),), stage=idle["stage"], decay=idle["decay"], staged=((1, 1),))
    add("lock_zero_reward", users=((21, 1, later, 0, 0),), delegators=((1, ((21, 0, 0, 0), (22, 1, 1, 0))),), profiles=((1, 11, 0),), stage=idle["stage"], decay=idle["decay"], staged=((1, 100),))
    add("lock_balance_overflow", users=((21, TOP - 40, later, 0, 0),), reserve=(1, 1 << 40), **{k: v for k, v in locks.items() if k != "reserve"})
    add("lock_validator_self_delegates", users=((1, 0, later, 0, 0),), delegators=((1, ((1, 1, 1, 0),)),), profiles=((1, 11, 2500),), stage=idle["stage"], decay=idle["decay"], staged=((1, 1000),))
    add("lock_tall_users", users=tuple((40 + k, k, later, 0, 0) for k in range(1, 24)) + ((21, 1, later, 0, 0), (22, 1, later, 0, 0), (1, 0, 0, 0, 0)), **locks)
    add("lock_sum_row_top", users=((21, 0, later, 0, 0),), delegators=((1, ((21, 1, 1, 0),)),), profiles=((1, 11, 0),), stage=idle["stage"], decay=idle["decay"], staged=((1, TOP),), reserve=(1, TOP))
    # snapshots
    add("snap_due_exact", round=19000, interval=10000, jail_interval=10000, hist=((9000, three),), **idle)
    add("snap_one_before", round=18999, interval=10000, jail_interval=10000, **idle)
    add("snap_one_after", round=19001, interval=10000, jail_interval=10000, **idle)
    add("snap_interval_zero_same_key", round=9000, interval=0, jail_interval=0, **idle)
    add("snap_interval_huge", interval=TOP, jail_interval=TOP, **idle)
    add("snap_interval_saturates_round_top", round=TOP, interval=TOP, jail_interval=TOP, **idle)
    add("snap_empty_history", hist=(), jail_hist=(), round=5, **idle)
    add("snap_empty_stakes", stakes=(), round=200000, **idle)
    add("snap_empty_jail_set", round=200000, jailed=(), **idle)
    add("snap_jail_set_copied", round=200000, jailed=(4, 9), **idle)
    add("snap_jail_tall_set", round=200000, jailed=tuple(range(10, 22)), **idle)
    add("snap_cap_trims_one", round=200000, cap=1, jail_cap=1, **idle)
    add("snap_cap_trims_two", round=200000, cap=2, jail_cap=2, hist=((8000, three), (8500, three), (9000, three)), jail_hist=((8000, ()), (8500, (1,)), (9000, ())), **idle)
    add("snap_cap_exact", round=200000, cap=2, jail_cap=2, **idle)
    add("snap_cap_zero", round=200000, cap=0, jail_cap=0, **idle)
    add("snap_jail_only", jail_interval=5, **idle)
    add("snap_stake_only", interval=5, **idle)
    add("snap_tall_history", round=200000, hist=tuple((1000 * k, three) for k in range(1, 10)), jail_hist=tuple((1000 * k, ()) for k in range(1, 10)), cur=9000, cap=40, jail_cap=40, **idle)
    add("snap_tall_stakes", round=200000, stakes=tuple((k, 1000 + k, 900 + k) for k in range(1, 24)), **idle)
    # decay
    for name, rows in (("above", ((1, 100, 200),)), ("equal", ((1, 100, 100),)), ("below", ((1, 200, 100),)), ("one_over", ((1, 100, 101),)), ("two_over", ((1, 0, 2),)), ("huge", ((1, 0, TOP),)), ("huge_gap", ((1, 5, 1 << 60),)),
                       ("three", ((1, 10, 20), (2, 30, 30), (3, 50, 40))), ("tall", tuple((k, 10 * k, 30 * k) for k in range(1, 30)))):
        add("decay_" + name, stakes=rows, stage=idle["stage"], dist=idle["dist"])
    add("decay_and_snapshot_same_tick", round=200000, stage=idle["stage"], dist=idle["dist"])
    add("decay_empty", stakes=(), stage=idle["stage"], dist=idle["dist"])
    add("snap_interval_wraps", interval=TOP - 100, jail_interval=TOP - 100, **idle)
    add("snap_interval_exact_top", interval=TOP - 9000, jail_interval=TOP - 9000, round=TOP, **idle)
    epoch_time = (date_word(1970, 1), 1000, 0)
    add("small_time_all_fire", now=epoch_time, stage=(1000, 999), dist=(1000, 999), decay=(1000, 999), staged=((1, 50),))
    add("small_time_none_fire", now=epoch_time, stage=(1000, 1000), dist=(1000, 1000), decay=(1000, 1000), staged=((1, 50),))
    add("small_time_last_above", now=epoch_time, stage=(7, 1 << 33), dist=(7, 1 << 33), decay=(7, 1 << 33))
    for name, fields in (("low_saturates", dict(hist=((TOP - 5, three),), cur=TOP - 4, low=TOP - 10, round=10)), ("low_saturates_below", dict(hist=((TOP - 1900, three),), cur=TOP - 1, low=TOP - 1999, round=10)), ("low_just_under_saturation", dict(hist=((TOP - 1900, three),), cur=TOP - 1, low=TOP - 2000, round=10)), ("edge_keep", dict(hist=((8800, three),), cur=9000, low=100)),
                         ("edge_drop", dict(hist=((8799, three),), cur=9000, low=100)), ("inside_2000", dict(hist=((1200, three),), cur=3000, low=1001)), ("at_2000", dict(hist=((1200, three),), cur=3001, low=1001)), ("low_clamps", dict(hist=((1500, three),), cur=3600, low=1500)),
                         ("low_clamps_drop", dict(hist=((1499, three),), cur=3600, low=1500)), ("tall", dict(hist=tuple((8000 + 10 * k, three) for k in range(9)), cur=8100, cap=20)), ("two_rows", dict(hist=((8000, three), (9000, three))))):
        add("dist_window_" + name, staged=((1, 60000),), delegators=((1, ((21, 1, 2, 9000), (22, 3, 4, 8100))),), interval=1 << 40, stage=idle["stage"], decay=idle["decay"], **fields)
    add("full_tick", round=200000, delegators=member, staged=((1, 123456),), users=((21, 1, later, 0, 0),), jailed=(12,))
    add("stage_reversed_snapshot_row", hist=((9000, ((3, 10 ** 12, 1), (1, 2 * 10 ** 12, 1))),), profiles=((1, 11, 0), (3, 13, 0)), staged=(), dist=idle["dist"], decay=idle["decay"])
    add("hist_cap_word_above_cur", hist=((1200, three),), cur=1300, low=1001, cap=1 << 20, dist=idle["dist"], decay=idle["decay"], interval=1 << 40)
    add("hist_cap_word_above_cur_dist", hist=((1200, three),), cur=1300, low=1001, cap=1 << 20, stage=idle["stage"], decay=idle["decay"], interval=1 << 40, staged=((1, 5000),))
    add("rate_amount_clamps_at_top", stage=(63500000000, 0), hist=((9000, ((1, TOP, 1),)),), b=1 << 62, dist=idle["dist"], decay=idle["decay"], reserve=(1, TOP), profiles=((1, 11, 0),))
    add("rate_amount_over_half_range", stage=(40000000000, 0), hist=((9000, ((1, TOP, 1),)),), b=1 << 62, dist=idle["dist"], decay=idle["decay"], reserve=(1, TOP), profiles=((1, 11, 0),))
    add("dist_commission_over_half_range", profiles=((1, 11, 6000),), stage=idle["stage"], decay=idle["decay"], staged=((1, TOP),), reserve=(1, 0))
    add("dist_member_over_half_range", profiles=((1, 11, 0),), delegators=((1, ((21, 3, 3, 0), (22, 2, 2, 0))),), stage=idle["stage"], decay=idle["decay"], staged=((1, TOP),), reserve=(1, 0))
    add("hist_empty_two_staged", hist=(), staged=((1, 50), (2, 60)), stage=idle["stage"], decay=idle["decay"], interval=1 << 40)
    add("dist_validator_missing_tall_members", delegators=tuple((k, ((21, 1, 1, 0),)) for k in range(2, 13)), staged=((1, 900), (13, 700)), profiles=((1, 11, 100), (13, 12, 100)), stage=idle["stage"], decay=idle["decay"])
    add("dist_new_member_tall_users", delegators=((1, ((20, 1, 1, 0), (70, 1, 1, 0))),), users=tuple((40 + k, k, 0, 0, 0) for k in range(1, 24)) + ((1, 4, 0, 0, 0),), staged=((1, 900),), stage=idle["stage"], decay=idle["decay"])
    add("row_signer_missing_tall_power", power=tuple(range(30, 46)), dist=idle["dist"], decay=idle["decay"])
    add("row_profile_missing_tall_profiles", profiles=tuple((k, 10 + k, 7) for k in range(5, 19)), dist=idle["dist"], decay=idle["decay"])
    add("row_signer_missing_tall_jail", jailed=tuple(range(50, 62)), power=(11, 12, 13), dist=idle["dist"], decay=idle["decay"])
    add("snap_deadline_saturated_one_before", round=TOP - 1, interval=TOP, jail_interval=TOP, **idle)
    add("assert_zero_duration", direct=True, stage=(0, 0))
    add("direct_guard_positive", direct=True)
    return out


def lcg(seed_value):
    state = [seed_value]

    def pick(limit):
        state[0] = (state[0] * 6364136223846793005 + 1442695040888963407) & TOP
        return (state[0] >> 33) % limit
    return pick


def vector_cases(count):
    cases = []
    pick = lcg(0x94A5)
    now = Case.FIELDS["now"]
    for at in range(count):
        ids = sorted({1 + pick(9) for _ in range(1 + pick(4))})
        size = 10 ** (3 + pick(11))
        snapshot = tuple((k, pick(size), pick(size)) for k in ids)
        profiles = tuple((k, 10 + k, pick(11000)) for k in ids if pick(5))
        power = tuple(10 + k for k in ids if pick(4))
        members = tuple((k, tuple((20 + m, pick(size), pick(size), 9000 if pick(2) else 1) for m in sorted({pick(6) for _ in range(1 + pick(4))}))) for k in ids if pick(3))
        users = tuple((20 + m, pick(size), (now[0] + (pick(5) - 2) * 16) if pick(2) else 0, pick(86400), 0) for m in sorted({pick(6) for _ in range(pick(4))}))
        cases.append(Case("vector_%d" % at, hist=((9000, snapshot),), stakes=snapshot, profiles=profiles, power=power, delegators=members, users=users, jailed=tuple(10 + k for k in ids if not pick(6)),
                          staged=tuple((k, pick(size)) for k in ids if pick(2)), reserve=(1 if pick(8) else 0, pick(size)), stage=(1 + pick(10 ** 7), 0) if pick(3) else (3600000, 1 << 40), dist=(3600000, 0) if pick(3) else (3600000, 1 << 40),
                          decay=(3600000, 0) if pick(2) else (3600000, 1 << 40), round=pick(30000), chain=pick(4), b=pick(10 ** 13), a=pick(4)))
    return cases


def check_cases(harness, cases, reach=None):
    outcomes = []
    for at, case in enumerate(cases):
        before = set()
        if reach is not None:
            harness.machine.seen, before = set(), harness.machine.seen
        got = harness.run(case)
        if reach is not None:
            for va in harness.machine.seen:
                reach.setdefault(va, []).append(at)
            harness.machine.seen |= before
        want = spec_run(case, harness.frozen_digest)
        if got != want:
            raise EvidenceError("case %s: %r != %r" % (case.name, got, want))
        outcomes.append(got)
    return outcomes


def direct_to(image, target):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xe8", text):
        at = match.start()
        if at + 5 <= len(text) and start + at + 5 + struct.unpack_from("<i", text, at + 1)[0] == target:
            hits.append(start + at)
    return hits


def slot_sites(image, slot):
    start, text = image.text_bytes()
    hits = []
    for match in re.finditer(b"\xff\x15", text):
        at = match.start()
        if at + 6 <= len(text) and start + at + 6 + struct.unpack_from("<i", text, at + 2)[0] == slot:
            hits.append(start + at)
    return hits


def caller_rows(image):
    relative = image.relative()
    if relative.get(SLOT_HOST) != HOST:
        raise EvidenceError("host slot")
    sites = sorted(slot_sites(image, SLOT_HOST))
    if len(sites) != 3:
        raise EvidenceError("host sites")
    rows = [("slot %#x" % SLOT_HOST, "tick_host", "%#x" % HOST, len(sites), " ".join("%#x" % site for site in sites))]
    for target in TARGETS[1:]:
        sites = sorted(direct_to(image, target))
        rows.append(("direct", NAMES[target], "%#x" % target, len(sites), " ".join("%#x" % site for site in sites[:12])))
    return rows


FIELDS = (
    ("stakes", 0x3E04DF, 6, 0x10, 0x3C12174, "mov"), ("validator_to_profile", 0x3E0517, 20, 0x150, 0x238D4C9, "lea"), ("stakes_decay_bucket_guard", 0x3E053F, 25, 0xA0, 0x238D51D, "lea"), ("jailed_signers", 0x3E0558, 14, 0xB0, 0x238D545, "lea"),
    ("native_token_reserve", 0x3E0594, 20, 0x60, 0x238D5CA, "mov"), ("stage_reward_bucket_guard", 0x3E05A8, 25, 0x100, 0x238D5E7, "lea"), ("validator_to_staged_rewards", 0x3E05C1, 27, 0x1E0, 0x238D60F, "lea"),
    ("distribute_reward_bucket_guard", 0x3E05DC, 30, 0x110, 0x238D62B, "lea"), ("user_states", 0x3DF9E4, 11, 0x1F8, 0x238D653, "lea"), ("pending_withdrawals", 0x3E05FA, 19, 0x210, 0x238D66F, "lea"),
)
CONSTANTS = (
    ("rate_numerator_and_year", 0x205FA0, struct.pack("<dd", 0.015, 31557600.0), "first lane over max(sqrt(T/b), floor), second lane over seconds"), ("rate_floor", 0x20AB88, struct.pack("<d", 0.015), "floor of sqrt(T/b)"),
    ("second_order_term", 0x20A8C8, struct.pack("<d", -0.5), "q*q*-0.5 + q"), ("millis_per_second", 0x20AF40, struct.pack("<d", 1000.0), "stage bucket width to seconds"), ("fraction_top", 0x20A528, struct.pack("<d", 1.01), "fraction above it pays 0"),
    ("commission_scale", 0x20B020, struct.pack("<d", 0.0001), "profile word +0x38 times this"), ("decay_share", 0x20A6A0, struct.pack("<d", 0.99), "share of the gap closed by one decay"), ("float_top", 0x20A510, struct.pack("<d", 18446744073709551616.0), "clamp before the cast"),
    ("float_inf", 0x20A4B0, struct.pack("<d", float("inf")), "infinite amount pays 0"), ("float_two63", 0x20A7F0, struct.pack("<d", 9223372036854775808.0), "second half of the u64 cast"), ("float_below_top", 0x20A218, bytes.fromhex("ffffffffffffef43"), "above it the cast gives u64::MAX"),
)
IMMEDIATES = (("window", 0x37D5E47, "4c8d82d0070000", "lea r8,[rdx+0x7d0]: the first 2000 keys past the low word use the low word as start"), ("back", 0x37D5E4E, "488d8838ffffff", "lea rcx,[rax-0xc8]: later the start is 200 keys back"),
              ("reserve_status", 0x3371D63, "66c78424d0030000be00", "mov word [rsp+0x3d0],0xbe: reserve add overflow"), ("half_bonus", 0x3371949, "48d1e8", "shr rax,1: lock bonus is half the reward"))
TEXTS = ((0x5A851E, 22), (0x5A8534, 35), (0x5A8557, 17), (0x5A8568, 13))


def proof_row(image, va):
    base = image.offset(va)
    code = bytes(image.blob[base:base + 32])
    return decode(lambda at, count: code[at - va:at - va + count], va), code


def field_rows(image):
    rows = []
    for name, key, size, offset, proof, op in FIELDS:
        text = bytes(image.blob[image.offset(key):image.offset(key) + size]).decode("ascii")
        if text != name:
            raise EvidenceError("key text %s" % text)
        row, code = proof_row(image, proof)
        operand = row.b if row.b and row.b[0] == "m" else row.a
        if operand[4] != offset:
            raise EvidenceError("field proof %#x" % proof)
        rows.append((name, "%#x" % key, "%#x" % offset, "%#x" % proof, code[:row.size].hex()))
    return rows


def constant_rows(image):
    rows = []
    for name, va, data, note in CONSTANTS:
        if bytes(image.blob[image.offset(va):image.offset(va) + len(data)]) != data:
            raise EvidenceError("constant %s" % name)
        rows.append((name, "%#x" % va, data.hex(), note))
    for name, va, form, note in IMMEDIATES:
        want = bytes.fromhex(form)
        if bytes(image.blob[image.offset(va):image.offset(va) + len(want)]) != want:
            raise EvidenceError("immediate %s" % name)
        rows.append((name, "%#x" % va, form, note))
    for va, size in TEXTS:
        rows.append(("label_text", "%#x" % va, "", bytes(image.blob[image.offset(va):image.offset(va) + size]).decode("ascii")))
    return rows


def rate_rows():
    rows = []
    for fraction in ("0.0000001", "0.0001", "0.000225", "0.01", "0.1", "0.2", "0.4", "0.5", "1", "4"):
        value = float(fraction)
        for hours in (1, 24):
            seconds_value = 3600.0 * hours
            root = max(math.sqrt(value), STATIC_RATE_BASE)
            q = STATIC_RATE_BASE / root
            per_bucket = rate_of(seconds_value, value, 1)
            rows.append((fraction, hours, "%.12g" % root, "%.12g" % q, "%.12g" % per_bucket, "%.12g" % (per_bucket * YEAR_SECONDS / seconds_value)))
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
            got = harness.run(case)
            if got != spec_run(case, harness.frozen_digest):
                return case
        except (Halt, EvidenceError, Panicked, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, TypeError, struct.error):
            return case
    return None


OPEN = "open: no named case tells this edit apart and it was not analysed further"
I, D, C = "immediate", "displacement", "condition"
CLASSES = (
    ("year at or below 0: time is negative, so the clamp to 0 hides the value", tuple((va, I) for va in (0x3996787, 0x399678E, 0x3996795, 0x399679B, 0x39967A5, 0x3996910, 0x3996917, 0x399691E, 0x3996924, 0x399692C, 0x3996B7E, 0x3996B85, 0x3996B8C, 0x3996B92, 0x3996B9A))),
    ("divide by 100 magic and its sign word: same quotient at every year used here", tuple((va, I) for va in (0x39967C2, 0x39967CC, 0x399693E, 0x3996948, 0x3996BAC, 0x3996BB6))),
    ("choice of the 32 bit or 64 bit divide: both give the same quotient", tuple((va, I) for va in (0x3996827, 0x3996994, 0x3996BFA))),
    ("label length read only by the metric block the tool hops over", tuple((va, I) for va in (0x3996860, 0x39969C5, 0x3996C2B))),
    ("unrolled tree descent: both arms walk the same way on trees this low", tuple((va, I) for va in (0x3996A77, 0x3996AAD, 0x3C10E35, 0x3C10F18, 0x3BE57B5, 0x3BE5898, 0x3371155, 0x3371238, 0x33713E5, 0x33714C8, 0x3C12285, 0x3C12378, 0x37D9B1E, 0x37D9B4D)) + tuple((va, C) for va in (0x3996A6E, 0x3996A7B, 0x37D9B15, 0x37D9B22))),
    ("edge pointer of a walk deeper than two levels: no fixture tree is that tall", tuple((va, D) for va in (0x3C10F03, 0x3BE5883, 0x3371223, 0x33714B3, 0x3C12363))),
    ("length read at the first row of a descended leaf: index 0 is below any length", tuple((va, D) for va in (0x3C10E93, 0x3BE5812, 0x3C12303))),
    ("iterator, vector and fresh node words read only by a stub, or rewritten before any read", tuple((va, I) for va in (0x3373634, 0x337368E, 0x33736CB, 0x33736E1, 0x3373748, 0x337375C, 0x3373767, 0x3373778, 0x3373784, 0x33737B5, 0x3370A95, 0x3370AEA, 0x3370B0E, 0x3371CE5, 0x3371D01, 0x3371D1D, 0x37D9AC5)) + ((0x337375C, D), (0x3373767, D), (0x3371CB1, D), (0x3371CDF, C))),
    ("short or long sort, and a free on the empty path: stubs that behave the same", ((0x337373E, I), (0x3373742, C), (0x3373C6F, I), (0x3373C73, C), (0x33737F5, C))),
    ("wrong key count in a node scan: extra slots hold zero keys, so the search ends on the same row", ((0x3BE5B19, D), (0x3BE5B6C, I), (0x3370C60, I), (0x3370E04, I), (0x3370FD5, D), (0x3371994, I))),
    ("lookup of a row this call just wrote: it never misses", ((0x3371883, I), (0x3371899, I), (0x337189D, C), (0x33719DE, I), (0x33717F6, D))),
    ("finite and clamp tests: the cast saturates the same way, and no amount here is negative or infinite", ((0x3BE5C21, I), (0x3BE5C32, I), (0x3BE5C45, C), (0x3BE5C4F, C), (0x3BE5CA2, I), (0x3370D8D, I), (0x337159B, I), (0x33715C1, C), (0x33715CB, C), (0x3371631, I), (0x3C121D5, I), (0x3C12211, I))),
    ("sign mask of the cast at or above 2^63: doubles that large are even, so the lost low bit is 0", tuple((va, I) for va in (0x3BE5C7F, 0x3370D6A, 0x337160E, 0x3C121F3))),
    ("add of the window to a low word past 2^64-2000: it always carries, so the sum is unused", ((0x37D9D14, I), (0x37D5E33, I))),
    ("entry copied to stack fields only the stubbed leaf insert would read, or a fresh node size, parent or bound", ((0x33BC0B7, D), (0x33BC0C3, D), (0x33BC0C7, D), (0x33BC156, I), (0x33BC166, I), (0x33BC188, I), (0x33BC1BB, D), (0x33BC600, D), (0x33BC60C, D), (0x33BC610, D), (0x33BC67A, I), (0x33BC68A, I), (0x33BC6AC, I))),
)
EXPECTED_SURVIVORS = {edit: text for text, edits in CLASSES for edit in edits}
POOL = {}
MUTANT_CASES = 400


def run_one(task):
    va, patch = task
    harness = Harness(POOL["image"], patch)
    harness.machine.step_limit = MUTANT_STEP_LIMIT
    places = POOL["reach"][va]
    places = places[::max(1, len(places) // MUTANT_CASES)]
    chosen = [POOL["cases"][at] for at in places]
    return first_failure(harness, chosen) is not None


def run_mutants(image, table, seen, cases, reach):
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    POOL.update(image=image, cases=cases, reach=reach)
    rows = [(target,) + edit for target in TARGETS for edit in edits_for(image, table[target], seen)]
    tasks = [(row[1], row[3]) for row in rows]
    try:
        with multiprocessing.get_context("fork").Pool(WORKERS) as pool:
            killed = pool.map(run_one, tasks, 8)
    except OSError:
        killed = [run_one(task) for task in tasks]
    return [(va, kind, "killed", "whole run") if dead else (va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), OPEN)) for (_, va, kind, _), dead in zip(rows, killed)]


def analyse(image, mutate=True, vectors=300):
    harness = Harness(image)
    cases = named_cases()
    reach = {}
    outcomes = check_cases(harness, cases, reach)
    seen = set(reach)
    check_cases(harness, vector_cases(vectors))
    table = {target: decode_range(image, *image.exact_fde(target)) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop", "ud2")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=vectors, unreached=unreached, callers=caller_rows(image), constants=constant_rows(image), fields=field_rows(image), rates=rate_rows())
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases, reach)
    return result


def short_rows(rows):
    if rows is None:
        return "none"
    return " ".join("%s:%s" % (row[0], "none" if row[1] is None else row[1]) if len(row) == 2 else "%d>%d/%d/%d" % row for row in rows) or "empty"


def describe(outcome):
    if outcome[0] == "panic":
        return outcome[1], "", "", "", "", ""
    if len(outcome) == 1:
        return "done", "", "", "", "", ""
    _, stage, sink, status, records, state, _, _ = outcome
    return "done", short_rows(stage), short_rows(sink), ",".join("%#x" % s for s in status), ",".join(records), hashlib.sha256(repr(state).encode()).hexdigest()[:16]


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("callers.tsv", ("reach", "role", "target", "sites", "addresses"), result["callers"])
    tsv("constants.tsv", ("name", "address", "bytes", "note"), result["constants"])
    tsv("field-names.tsv", ("key", "key_address", "offset", "proof_address", "proof_bytes"), result["fields"])
    tsv("rate-table.tsv", ("T_over_b", "bucket_hours", "root_after_floor", "q", "rate_per_bucket", "per_bucket_times_buckets_per_year"), result["rates"])
    tsv("outcomes.tsv", ("case", "end", "stage_rows", "sink_rows", "status", "recorder", "state_digest"), [(case.name,) + describe(outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"], "metric_hops": ["%#x->%#x" % hop for hop in (HOP_STAGE, HOP_DECAY, HOP_DIST)],
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
