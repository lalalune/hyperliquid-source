#!/usr/bin/env python3
"""Pin node #94 perp dex limit votes: five VoteGlobal arms, their twelve writers and the override map.

The real dispatcher arms, writers and tree helpers run from the dispatcher entry on a state image with real rows. A
separately written rule list predicts the status, the stored words and every other heap byte, and every reached
conditional row, immediate and field offset is mutated. No objdump or readelf output is parsed and the binary is never
executed. Standard library only.

    python3 tools/perp_dex_limit_votes.py --out <dir>
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
HEAP_SIZE = 0x40000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 3000000
MUTANT_STEP_LIMIT = 200000


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

OK = 0x186
TAG_NUMBER = 0x13F
TAG_LENGTH = 0x143
TAG_DEX = 0x141
TAG_LOOKUP = 0x123
CAP = 0x0CCCCCCCCCCCCCCC
NO_NAME = 1 << 63
ONE_MILLION = 1000000
FLOOR_TRANSFER = 100000000000
ROW_SIZE = 0x2F0
ROW_TAG = 0x230
TAG_MAIN = 3
LIMITS_AT = 0x1A8
OVERRIDE_AT = 0x1D0
WORD_OVERRIDE = 71
WORD_TRANSFER = 83
WORD_SZ = 84
WORD_TOTAL = 85
WORD_USERS = 87
WORDS = (WORD_OVERRIDE, WORD_TRANSFER, WORD_SZ, WORD_TOTAL, WORD_USERS)
FIELDS = {WORD_TOTAL: (0x8,), WORD_SZ: (0x10,), WORD_TRANSFER: (0x18, 0x20), WORD_USERS: (0x28,)}
SLOT_DEX = 0x5773EB8
SLOT_MAIN_ROW = 0x5773D80
SLOT_ASSET = 0x5773318
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_COPY = 0x576DFE0
SLOT_MOVE = 0x576E0E0
PANIC_SLOTS = (0x576DFB8, 0x576E020, 0x576E470, 0x576E108, 0x576E098, 0x576E468, 0x576DFC8, 0x576E128)
RESUME = 0x5660110
MARK_BASE = 0x7700000000
TEXT_TABLE = 0x59A8D0
TOP = MASK[8]
FILL_END = 0x8000
NODES = HEAP_BASE + FILL_END
NODE_END = HEAP_BASE + 0x3F000
OUT = HEAP_BASE + 0x100
ACTION = HEAP_BASE + 0x200
NAME = HEAP_BASE + 0x400
S = HEAP_BASE + 0x1000
ROWS = HEAP_BASE + 0x6000
ROW_ROOM = 6
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(FILL_END))


class Copy:
    def __init__(self, name, dispatch, table, base, chain, defaults, writers, insert, remove):
        self.name, self.dispatch, self.table, self.base, self.chain, self.defaults = name, dispatch, table, base, chain, defaults
        self.writers, self.insert, self.remove = writers, insert, remove


COPIES = (
    Copy("a", 0x2355F40, 0x3DD1B8, 0x5B8, 0x8F2, 0x3908, {WORD_TOTAL: 0x235F110, WORD_SZ: 0x235EA90, WORD_TRANSFER: 0x235EF30, WORD_USERS: 0x235ECE0}, 0x285F5A0, 0x2866BF0),
    Copy("b", 0x4CAA870, 0x711064, 0x5B8, 0x8F2, 0x3908, {WORD_TOTAL: 0x4CBCF80, WORD_SZ: 0x4CBC280, WORD_TRANSFER: 0x4CBC970, WORD_USERS: 0x4CBBB90}, 0x4938EA0, 0x4945820),
    Copy("c", 0x4CB3200, 0x711244, 0x1038, 0x1372, 0x4388, {WORD_TOTAL: 0x4CBC030, WORD_SZ: 0x4CBCB50, WORD_TRANSFER: 0x4CBCDA0, WORD_USERS: 0x4CBC4D0}, 0x4938EA0, 0x4945820),
)
WRITERS = tuple(sorted(copy.writers[word] for copy in COPIES for word in copy.writers))
MAP_CODE = tuple(sorted({copy.insert for copy in COPIES} | {copy.remove for copy in COPIES}))
TARGETS = WRITERS + MAP_CODE
NAMES = {}
for _copy in COPIES:
    for _word, _name in ((WORD_TOTAL, "total_oi_cap"), (WORD_SZ, "oi_sz_cap"), (WORD_TRANSFER, "transfer_limits"), (WORD_USERS, "max_n_users")):
        NAMES[_copy.writers[_word]] = "set_%s_%s" % (_name, _copy.name)
    NAMES[_copy.insert] = "override_insert_%s" % ("a" if _copy.name == "a" else "bc")
    NAMES[_copy.remove] = "override_remove_%s" % ("a" if _copy.name == "a" else "bc")
L_MAP = (8, 0x60, 0xBA, 0xC0, 0xB8)
LIMIT_KEYS = (
    (0x233B03D, "4d8b6710", 0x233B048, 0x10, 0x12, "oi_sz_cap_per_perp"),
    (0x233AFF5, "4d8b6708", 0x233B000, 0x08, 0x0D, "total_oi_cap2"),
    (0x233B085, "4d8b6718", 0x233B090, 0x18, 0x11, "max_transfer_ntl2"),
    (0x233B0CD, "4d8b6720", 0x233B0D8, 0x20, 0x26, "max_under_initial_margin_transfer_ntl2"),
    (0x233B12E, "498b17", 0x233B114, 0x00, 0x0E, "daily_px_range"),
    (0x233B149, "498b5728", 0x23D92EE, 0x28, 0x1A, "max_n_users_with_positions"),
)
VARIANT_KEYS = (
    (0x233CA57, "80be8800000003", 0x233CA88, 0x88, 4, "Main"),
    (0x233CBD9, "498d7710", 0x233CBBB, 0x10, 0x12, "asset_to_recent_oi"),
    (0x233CC17, "498d7728", 0x233CBF9, 0x28, 0x1A, "override_max_oi_per_second"),
    (0x233CC58, "4c89fe", 0x233CC37, 0x00, 0x1C, "reset_recent_oi_bucket_guard"),
    (0x233CC92, "4983c740", 0x233CC74, 0x40, 0x1B, "assets_at_open_interest_cap"),
    (0x233CB44, "488d35", 0x233CB44, 0x88, 4, "Hip3"),
    (0x233CCF9, "4c89fe", 0x233CCD8, 0x00, 6, "limits"),
    (0x233CD33, "498b7760", 0x233CD15, 0x60, 6, "schema"),
    (0x233CD71, "4983c768", 0x233CD53, 0x68, 5, "state"),
    (0x233CAE4, "498d7f30", 0x233CDD6, 0x30, 0x1E, "hip3_backstop_liquidator_state"),
)
SERDE = (b"struct variant MainOrHip3::Main with 4 elements", b"struct variant MainOrHip3::Hip3 with 4 elements",
         b"struct variant VoteGlobalAction::SetPerpDexTransferLimits with 3 elements", b"struct variant VoteGlobalAction::SetPerpDexOpenInterestCap with 2 elements",
         b"struct variant VoteGlobalAction::SetPerpDexOpenInterestSzCapPerPerp with 2 elements", b"struct variant VoteGlobalAction::SetPerpDexMaxNUsersWithPositions with 2 elements",
         b"tuple variant VoteGlobalAction::SetMaxOiPerSecond with 2 elements", b"struct variant VoteGlobalAction::SetPerpDexDailyPxRange with 2 elements")
TAG_TEXTS = {TAG_NUMBER: "Invalid input number", TAG_LENGTH: "Invalid input length", TAG_DEX: "Invalid perp DEX"}


class Case:
    DEFAULTS = dict(copy=0, word=WORD_TOTAL, dex=None, cap=None, v=2000000, w=0, some=1, chain=3, tags=(TAG_MAIN, 0, 1, 2), hit=1, fail=False, asset=7, tree=(), main=0)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, value)
        for key, value in fields.items():
            if key not in self.DEFAULTS:
                raise EvidenceError("unknown case field %s" % key)
            setattr(self, key, value)


def row_word(index, offset):
    return 0x5000000 + index * 0x100000 + offset


def default_word(offset):
    return 0x7000000 + offset


def spec_writer(case, copy, after):
    """The rule list for the 4 writer families."""
    offsets = FIELDS[case.word]
    values = (case.v, case.w)
    name = case.dex
    if name is None:
        for offset, value in zip(offsets, values):
            struct.pack_into("<Q", after, S - HEAP_BASE + copy.defaults + offset, value)
        for index, tag in enumerate(case.tags):
            if tag != TAG_MAIN:
                for offset, value in zip(offsets, values):
                    at = ROWS - HEAP_BASE + index * ROW_SIZE + LIMITS_AT + offset
                    struct.pack_into("<Q", after, at, max(value, row_word(index, offset)))
        return (OK,), True
    if len(name) > 100:
        return (TAG_LENGTH, (8, len_cap(case)), (0x18, len(name))), True
    if case.fail:
        return ("object",), True
    if case.tags[case.hit] == TAG_MAIN:
        return (TAG_DEX,), True
    for offset, value in zip(offsets, values):
        struct.pack_into("<Q", after, ROWS - HEAP_BASE + case.hit * ROW_SIZE + LIMITS_AT + offset, value)
    return (OK,), True


def len_cap(case):
    return case.cap if case.cap is not None else len(case.dex)


def spec_action(case, after):
    copy = COPIES[case.copy]
    word, v, w = case.word, case.v, case.w
    if word == WORD_OVERRIDE:
        return spec_override(case)
    if word == WORD_TRANSFER:
        if v >= CAP:
            return (TAG_NUMBER, (8, v)), True
        if w >= CAP:
            return (TAG_NUMBER, (8, w)), True
        test = case.chain == 2
        scale, low = (2, 0) if test else (5, FLOOR_TRANSFER)
        if not (scale * v <= w and v >= low and w >= 10 * low):
            return (TAG_NUMBER,), True
        return spec_writer(case, copy, after)
    if v >= CAP:
        return (TAG_NUMBER, (8, v)), True
    if word == WORD_TOTAL and v < ONE_MILLION:
        return (TAG_NUMBER,), True
    return spec_writer(case, copy, after)


def spec_override(case):
    """Returns the status words; the map result comes from spec_map."""
    if len(case.dex) > 100:
        return ("length",), True
    if case.fail:
        return ("object",), True
    if case.tags[case.main] != TAG_MAIN:
        return (OK,), True
    if case.some and case.v >= CAP:
        return (TAG_NUMBER, (8, case.v)), True
    return (OK,), True


def spec_map(case):
    items = dict(case.tree)
    if case.word != WORD_OVERRIDE or len(case.dex) > 100 or case.fail or case.tags[case.main] != TAG_MAIN:
        return tuple(sorted(items.items()))
    if not case.some:
        items.pop(case.asset, None)
    elif ONE_MILLION <= case.v < CAP:
        items[case.asset] = case.v
    return tuple(sorted(items.items()))


def spec_run(case, before):
    after = bytearray(before)
    status, frees = spec_action(case, after)
    return bytes(after), status, frees, spec_map(case)


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        hooks = {SLOT_FREE: self.on_free, SLOT_ALLOC: self.on_alloc, SLOT_COPY: self.on_copy, SLOT_MOVE: self.on_copy, SLOT_DEX: self.on_dex, SLOT_MAIN_ROW: self.on_main_row, SLOT_ASSET: self.on_asset}
        for slot in PANIC_SLOTS:
            hooks[slot] = self.on_panic
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        machine.real = RealCode.ALL
        machine.calls = {RESUME: self.on_panic}
        self.case = None
        self.events = []
        self.live = {}
        self.node_cur = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def on_panic(self, machine):
        raise Panicked("panic path")

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        self.expect(size in (L_MAP[3], L_MAP[3] + 0x60), "tree node size")
        at = self.node_cur
        self.node_cur += (size + 15) & ~15
        self.expect(self.node_cur <= NODE_END, "allocator room")
        self.live[at] = size
        machine.memory.put_bytes(at, bytes([0x77]) * size)
        machine.regs[RAX] = at

    def on_free(self, machine):
        at, size = machine.regs[RDI], machine.regs[RSI]
        self.expect(self.live.pop(at, None) == size, "free of a live block with its size")
        self.events.append("free")

    def on_copy(self, machine):
        dst, src, size = machine.regs[RDI], machine.regs[RSI], machine.regs[RDX]
        machine.memory.put_bytes(dst, machine.memory.bytes_at(src, size))
        machine.regs[RAX] = dst

    def object_bytes(self, tag):
        return struct.pack("<H", tag) + bytes((0x41 + index) & 0xFF for index in range(2, 0x60))

    def on_dex(self, machine):
        case = self.case
        copy = COPIES[case.copy]
        self.expect(machine.regs[RSI] == S + copy.base, "dex table argument")
        self.expect(machine.regs[RDX] == NAME and machine.regs[RCX] == len(case.dex), "dex name argument")
        self.events.append("dex")
        out = machine.regs[RDI]
        if case.fail:
            machine.memory.put_bytes(out, self.object_bytes(TAG_LOOKUP))
        else:
            machine.memory.write(out, 2, OK)
            machine.memory.write(out + 8, 8, ROWS + case.hit * ROW_SIZE)

    def on_main_row(self, machine):
        copy = COPIES[self.case.copy]
        self.expect(machine.regs[RDI] == S + copy.base and machine.regs[RSI] & 0xFFFFFFFF == 0, "main row arguments")
        self.events.append("main_row")
        machine.regs[RAX] = ROWS + self.case.main * ROW_SIZE

    def on_asset(self, machine):
        case = self.case
        regs = machine.regs
        self.expect(regs[RSI] == NAME and regs[RDX] == len(case.dex) and regs[RCX] == ROWS + case.main * ROW_SIZE, "asset arguments")
        self.events.append("asset")
        out = regs[RDI]
        if case.fail:
            machine.memory.put_bytes(out, self.object_bytes(TAG_LOOKUP))
        else:
            machine.memory.write(out, 2, OK)
            machine.memory.write(out + 8, 8, case.asset)

    def node(self, items):
        memory = self.machine.memory
        key_at, val_at, len_at, edge_at, _ = L_MAP
        at = self.node_cur
        self.node_cur += edge_at
        self.live[at] = edge_at
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(edge_at)))
        memory.write(at, 8, 0)
        memory.write(at + len_at, 2, len(items))
        for slot in range(len(items), 11):
            memory.write(at + key_at + 8 * slot, 8, self.case.asset)
        for slot, (key, value) in enumerate(items):
            memory.write(at + key_at + 8 * slot, 8, key)
            memory.write(at + val_at + 8 * slot, 8, value)
        return at

    def tree(self, items):
        """A leaf, or a root with leaves below it."""
        items = sorted(items)
        memory = self.machine.memory
        if not items:
            return 0, 0xFEED, 0
        if len(items) <= 11:
            return self.node(items), 0, len(items)
        key_at, val_at, len_at, edge_at, index_at = L_MAP
        parts, seps, at = [], [], 0
        while len(items) - at > 11:
            parts.append(items[at:at + 5])
            seps.append(items[at + 5])
            at += 6
        parts.append(items[at:])
        root_size = edge_at + 0x60
        kids = [self.node(part) for part in parts]
        root = self.node_cur
        self.node_cur += root_size
        self.live[root] = root_size
        memory.put_bytes(root, bytes((0x31 + 7 * index) & 0xFF or 1 for index in range(root_size)))
        memory.write(root, 8, 0)
        memory.write(root + len_at, 2, len(seps))
        for slot in range(len(seps), 11):
            memory.write(root + key_at + 8 * slot, 8, self.case.asset)
        for slot, (key, value) in enumerate(seps):
            memory.write(root + key_at + 8 * slot, 8, key)
            memory.write(root + val_at + 8 * slot, 8, value)
        for slot, kid in enumerate(kids):
            memory.write(root + edge_at + 8 * slot, 8, kid)
            memory.write(kid, 8, root)
            memory.write(kid + index_at, 2, slot)
        return root, 1, len(items)

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(HEAP_SIZE)
        memory.heap[:FILL_END] = HEAP_FILL
        self.case = case
        self.events = []
        self.live = {}
        self.node_cur = NODES
        copy = COPIES[case.copy]
        memory.write(S + copy.chain, 1, case.chain)
        memory.write(S + copy.base + 8, 8, ROWS)
        memory.write(S + copy.base + 0x10, 8, len(case.tags))
        for index, offset in enumerate((0, 8, 0x10, 0x18, 0x20, 0x28)):
            memory.write(S + copy.defaults + offset, 8, default_word(offset))
        for index in range(ROW_ROOM + 1):
            row = ROWS + index * ROW_SIZE
            for offset in (0, 8, 0x10, 0x18, 0x20, 0x28):
                memory.write(row + LIMITS_AT + offset, 8, row_word(index, offset))
            tag = case.tags[index] if index < len(case.tags) else 0
            memory.write(row + ROW_TAG, 1, tag)
        name = case.dex
        if case.word == WORD_OVERRIDE:
            root, height, count = self.tree(case.tree)
            row = ROWS + case.main * ROW_SIZE + OVERRIDE_AT
            memory.write(row, 8, root)
            memory.write(row + 8, 8, height)
            memory.write(row + 0x10, 8, count)
            memory.write(ACTION, 8, case.word)
            memory.write(ACTION + 8, 8, case.some)
            memory.write(ACTION + 0x10, 8, case.v)
            cap = len(name) if case.cap is None else case.cap
            memory.write(ACTION + 0x18, 8, cap)
            memory.write(ACTION + 0x20, 8, NAME)
            memory.write(ACTION + 0x28, 8, len(name))
            memory.put_bytes(NAME, name)
            if cap:
                self.live[NAME] = cap
        else:
            memory.write(ACTION, 8, case.word)
            if name is None:
                memory.write(ACTION + 8, 8, NO_NAME)
            else:
                cap = len(name) if case.cap is None else case.cap
                memory.write(ACTION + 8, 8, cap)
                memory.write(ACTION + 0x10, 8, NAME)
                memory.write(ACTION + 0x18, 8, len(name))
                memory.put_bytes(NAME, name)
                if cap:
                    self.live[NAME] = cap
            memory.write(ACTION + 0x20, 8, case.v)
            memory.write(ACTION + 0x28, 8, case.w)
        return bytes(memory.heap[:FILL_END])

    def walk(self, root, height):
        memory = self.machine.memory
        key_at, val_at, len_at, edge_at, _ = L_MAP
        rows = []

        def visit(at, level, parent, index):
            size = memory.read(at + len_at, 2)
            self.expect(memory.read(at, 8) == parent, "parent link")
            if parent:
                self.expect(memory.read(at + L_MAP[4], 2) == index, "parent index")
            for slot in range(size + 1):
                if level:
                    visit(memory.read(at + edge_at + 8 * slot, 8), level - 1, at, slot)
                if slot < size:
                    rows.append((memory.read(at + key_at + 8 * slot, 8), memory.read(at + val_at + 8 * slot, 8)))
        if root:
            visit(root, height, 0, 0)
        return tuple(rows)

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        memory = machine.memory
        copy = COPIES[case.copy]
        try:
            machine.run(copy.dispatch, {RDI: OUT, RSI: ACTION, RDX: S})
        except Panicked as panic:
            return before, ("panic", str(panic), None, None, None)
        now = bytearray(memory.heap[:FILL_END])
        out = bytes(now[OUT - HEAP_BASE:OUT - HEAP_BASE + 0x60])
        now[OUT - HEAP_BASE:OUT - HEAP_BASE + 0x60] = before[OUT - HEAP_BASE:OUT - HEAP_BASE + 0x60]
        items = ()
        if case.word == WORD_OVERRIDE:
            row = ROWS + case.main * ROW_SIZE + OVERRIDE_AT
            items = self.walk(memory.read(row, 8), memory.read(row + 8, 8))
            self.expect(memory.read(row + 0x10, 8) == len(items), "map length word")
            at = row - HEAP_BASE
            now[at:at + 24] = before[at:at + 24]
        return before, ("run", out, bytes(now), items, tuple(self.events), dict(self.live))


class RealCode:
    ALL = frozenset()


def collect_real(image):
    """Writers, map code and every function those reach by direct calls; the dispatcher rows run too."""
    seen = set(TARGETS)
    todo = list(seen)
    while todo:
        for row in decode_range(image, *image.exact_fde(todo.pop())):
            if row.op == "call" and row.target not in seen and row.target != RESUME and row.target < 0x5660000:
                seen.add(row.target)
                todo.append(row.target)
    return frozenset(seen)


def out_ok(case, got, status):
    out = got[1]
    word = struct.unpack_from("<H", out)[0]
    if status[0] == "object":
        return out == Harness.object_bytes(None, TAG_LOOKUP)
    if status[0] == "length":
        return word == TAG_LENGTH
    if word != status[0]:
        return False
    return all(struct.unpack_from("<Q", out, at)[0] == value for at, value in status[1:])


def same(case, got, want):
    if got[0] != "run":
        return False
    after, status, frees, items = want
    if got[2] != after:
        return False
    if got[3] != items or not out_ok(case, got, status):
        return False
    live = got[5]
    keep = NAME in live
    if frees and keep:
        return False
    if not frees and not keep:
        return False
    return True


def diff_text(case, got, want):
    if got[0] != "run":
        return " " + repr(got[:2])
    now, after = got[2], want[0]
    diffs = [HEAP_BASE + index for index in range(len(now)) if now[index] != after[index]][:6]
    return " out %s want %r map %r want %r heap diffs %s live %s events %r" % (got[1][:32].hex(), want[1], got[3], want[3], [hex(x) for x in diffs], sorted(hex(x) for x in got[5]), got[4])


def lcg(seed):
    state = seed
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state >> 11


def names(count):
    return bytes((0x61 + index % 26) for index in range(count))


def base_cases():
    cases = []

    def add(label, **fields):
        cases.append(Case(label, **fields))

    for index in range(3):
        tag = "copy%d " % index
        for word, label in ((WORD_TOTAL, "total"), (WORD_SZ, "sz"), (WORD_USERS, "users"), (WORD_TRANSFER, "transfer")):
            v, w = (FLOOR_TRANSFER, 10 * FLOOR_TRANSFER) if word == WORD_TRANSFER else (ONE_MILLION, 0)
            name = tag + label
            add(name + " all rows raise", copy=index, word=word, v=TOP >> 5 & CAP - 1, w=CAP - 1, dex=None)
            add(name + " all rows keep the larger stored word", copy=index, word=word, v=v, w=w, dex=None)
            add(name + " row equal to the new word", copy=index, word=word, v=row_word(1, FIELDS[word][0]), w=row_word(1, FIELDS[word][-1]), tags=(0, 0), dex=None) if word != WORD_TRANSFER else None
            for count in range(0, ROW_ROOM + 1):
                add(name + " %d rows no Main" % count, copy=index, word=word, v=v + 0x5100000, w=w + 0x51000000, tags=(1,) * count, dex=None)
                add(name + " %d rows all Main" % count, copy=index, word=word, v=v + 0x5100000, w=w + 0x51000000, tags=(TAG_MAIN,) * count, dex=None)
                add(name + " %d rows keep the stored word" % count, copy=index, word=word, v=v, w=w, tags=(0,) * count, dex=None)
                add(name + " %d rows mixed" % count, copy=index, word=word, v=v + 0x5100000, w=w + 0x51000000, tags=tuple(TAG_MAIN if slot % 2 else 2 for slot in range(count)), dex=None)
            add(name + " named sets a lower word", copy=index, word=word, v=v, w=w, dex=names(9))
            add(name + " named raises", copy=index, word=word, v=v + 0x7000000, w=w + 0x70000000, dex=names(9), hit=2, tags=(TAG_MAIN, 1, 2, 0))
            add(name + " named empty name", copy=index, word=word, v=v, w=w, dex=b"", cap=0)
            add(name + " named capacity above length", copy=index, word=word, v=v, w=w, dex=names(9), cap=32)
            add(name + " name 100 bytes", copy=index, word=word, v=v, w=w, dex=names(100))
            add(name + " name 101 bytes", copy=index, word=word, v=v, w=w, dex=names(101))
            add(name + " name 101 bytes capacity 0x40", copy=index, word=word, v=v, w=w, dex=names(101), cap=0x140)
            add(name + " lookup error", copy=index, word=word, v=v, w=w, dex=names(9), fail=True)
            add(name + " lookup error with capacity", copy=index, word=word, v=v, w=w, dex=names(9), fail=True, cap=48)
            add(name + " named Main refused", copy=index, word=word, v=v, w=w, dex=names(9), hit=0)
            add(name + " named Main refused empty", copy=index, word=word, v=v, w=w, dex=b"", cap=0, hit=0)
            add(name + " first number at the cap", copy=index, word=word, v=CAP, w=CAP - 1, dex=names(9))
            add(name + " first number at the cap no name", copy=index, word=word, v=CAP, w=CAP - 1, dex=None)
            add(name + " first number below the cap", copy=index, word=word, v=CAP - 1, w=TOP // 16, dex=None) if word != WORD_TRANSFER else None
            add(name + " first number top", copy=index, word=word, v=TOP, w=CAP - 1, dex=names(9))
        for chain in (0, 1, 2, 3, 4):
            low = 0 if chain == 2 else FLOOR_TRANSFER
            scale = 2 if chain == 2 else 5
            fields = dict(copy=index, word=WORD_TRANSFER, chain=chain, dex=None)
            base = max(low, 3 * 10 ** 9)
            floor_w = max(10 * low, scale * base)
            add(tag + "chain %d pair at both floors" % chain, v=low, w=10 * low, **fields)
            add(tag + "chain %d pair exact ratio" % chain, v=base, w=floor_w, **fields)
            add(tag + "chain %d pair one under ratio" % chain, v=base, w=floor_w - 1, **fields)
            add(tag + "chain %d first one under its floor" % chain, v=low - 1 if low else 0, w=floor_w, **fields)
            add(tag + "chain %d second one under its floor" % chain, v=low, w=10 * low - 1 if low else 0, **fields)
            add(tag + "chain %d second number at the cap" % chain, v=base, w=CAP, **fields)
            add(tag + "chain %d second number top" % chain, v=base, w=TOP, **fields)
            add(tag + "chain %d second number at the cap, first too" % chain, v=CAP, w=CAP, **fields)
            add(tag + "chain %d largest admitted pair" % chain, v=(CAP - 1) // scale, w=CAP - 1, **fields)
            add(tag + "chain %d first over the ratio at the top" % chain, v=(CAP - 1) // scale + 1, w=CAP - 1, **fields)
            add(tag + "chain %d named" % chain, v=base, w=floor_w, copy=index, word=WORD_TRANSFER, chain=chain, dex=names(5))
            add(tag + "chain %d refused named frees" % chain, v=base, w=floor_w - 1, copy=index, word=WORD_TRANSFER, chain=chain, dex=names(5))
            add(tag + "chain %d refused empty capacity" % chain, v=base, w=floor_w - 1, copy=index, word=WORD_TRANSFER, chain=chain, dex=b"", cap=0)
        add(tag + "total one under a million", copy=index, word=WORD_TOTAL, v=ONE_MILLION - 1, dex=None)
        add(tag + "total zero", copy=index, word=WORD_TOTAL, v=0, dex=names(4))
        add(tag + "total named under a million frees", copy=index, word=WORD_TOTAL, v=ONE_MILLION - 1, dex=names(4))
        add(tag + "sz zero admitted", copy=index, word=WORD_SZ, v=0, dex=names(4))
        add(tag + "sz zero no name keeps rows", copy=index, word=WORD_SZ, v=0, dex=None)
        add(tag + "users zero admitted", copy=index, word=WORD_USERS, v=0, dex=names(4))
        add(tag + "users zero no name keeps rows", copy=index, word=WORD_USERS, v=0, dex=None)
        for label, items in (("empty map", ()), ("one row", ((3, 5),)), ("hit row", ((3, 5), (7, 9), (9, 11))), ("full leaf", tuple((slot * 2 + 1, slot + 100) for slot in range(11))),
                             ("root", tuple((slot * 2 + 1, slot + 100) for slot in range(16)))):
            fields = dict(copy=index, word=WORD_OVERRIDE, dex=names(3), tree=items)
            add(tag + "override set a million, " + label, v=ONE_MILLION, **fields)
            add(tag + "override set one under, " + label, v=ONE_MILLION - 1, **fields)
            add(tag + "override set below cap, " + label, v=CAP - 1, **fields)
            add(tag + "override at cap, " + label, v=CAP, **fields)
            add(tag + "override clear, " + label, some=0, v=CAP, **fields)
            add(tag + "override clear other asset, " + label, some=0, asset=8, **fields)
            add(tag + "override small asset, " + label, v=ONE_MILLION, asset=0, **fields)
            add(tag + "override large asset, " + label, v=ONE_MILLION, asset=99, **fields)
            add(tag + "override key equal to a row, " + label, v=ONE_MILLION + 5, asset=5, **fields)
            add(tag + "override Hip3 row ignored set, " + label, v=ONE_MILLION, tags=(1, 0), **fields)
            add(tag + "override Hip3 row ignored cap, " + label, v=CAP, tags=(2, 0), **fields)
            add(tag + "override Hip3 row ignored clear, " + label, some=0, tags=(0, 0), **fields)
            add(tag + "override asset lookup error, " + label, v=ONE_MILLION, fail=True, **fields)
        for size in (12, 13, 16, 18):
            items = tuple((slot * 2 + 1, slot + 100) for slot in range(size))
            for key, _ in items:
                add(tag + "override clear key %d of %d" % (key, size), copy=index, word=WORD_OVERRIDE, dex=names(3), tree=items, some=0, asset=key)
                add(tag + "override replace key %d of %d" % (key, size), copy=index, word=WORD_OVERRIDE, dex=names(3), tree=items, v=ONE_MILLION + key, asset=key)
                add(tag + "override add after key %d of %d" % (key, size), copy=index, word=WORD_OVERRIDE, dex=names(3), tree=items, v=ONE_MILLION + key, asset=key + 1)
        add(tag + "override name 100", copy=index, word=WORD_OVERRIDE, dex=names(100), v=ONE_MILLION)
        add(tag + "override name 101", copy=index, word=WORD_OVERRIDE, dex=names(101), v=ONE_MILLION)
        add(tag + "override empty name", copy=index, word=WORD_OVERRIDE, dex=b"", cap=0, v=ONE_MILLION)
        add(tag + "override capacity", copy=index, word=WORD_OVERRIDE, dex=names(3), cap=40, v=ONE_MILLION)
        add(tag + "override second row is the first dex", copy=index, word=WORD_OVERRIDE, dex=names(3), main=1, tags=(0, TAG_MAIN), v=ONE_MILLION)
    return [case for case in cases if case is not None]


def vector_cases(count):
    random = lcg(0x5EED1)
    cases = []
    for index in range(count):
        copy = next(random) % 3
        word = WORDS[next(random) % 5]
        chain = next(random) % 4
        size = next(random) % 7
        tags = tuple((TAG_MAIN if next(random) % 3 == 0 else next(random) % 3) for _ in range(size))
        kind = next(random) % 4
        v = (0x4F00000 + next(random) % 0x300000, ONE_MILLION + next(random) % 3 - 1, next(random) % (CAP * 2), FLOOR_TRANSFER + next(random) % 10 ** 13)[kind]
        w = (v * (1 + next(random) % 12) + next(random) % 3 - 1) & TOP
        if word == WORD_OVERRIDE:
            tree = tuple(sorted({next(random) % 30: 7 + slot for slot in range(next(random) % 15)}.items()))
            cases.append(Case("vector %d" % index, copy=copy, word=word, v=v, some=next(random) % 2, tree=tree, asset=next(random) % 30, dex=names(next(random) % 4 + 1), tags=(tags or (TAG_MAIN,)), fail=next(random) % 11 == 0))
        else:
            hit = next(random) % size if size else 0
            name = None if next(random) % 2 or not size else names(next(random) % 103)
            cases.append(Case("vector %d" % index, copy=copy, word=word, v=v, w=w, chain=chain, tags=tags, hit=hit, dex=name, fail=next(random) % 11 == 0))
    return cases


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before)
        if not same(case, got, want):
            raise EvidenceError("case disagrees with the rule list: %s" % case.name + diff_text(case, got, want))
        outcomes.append(got)
    return outcomes


def text_at(image, arm):
    start = image.offset(arm)
    data = bytes(image.blob[start:start + 40])
    at = data.find(b"\x48\x8d\x35")
    if at < 0 or data[at + 7] != 0xBA:
        return ""
    target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    size = struct.unpack_from("<I", data, at + 8)[0]
    return bytes(image.blob[image.offset(target):image.offset(target) + size]).decode()


def arm_of(image, table, index):
    return table + struct.unpack_from("<i", image.blob, image.offset(table) + 4 * index)[0]


def text_rows(image):
    rows = []
    for tag, want in sorted(TAG_TEXTS.items()):
        text = text_at(image, arm_of(image, TEXT_TABLE, tag))
        if text != want:
            raise EvidenceError("tag text %#x" % tag)
        rows.append(("%#x" % tag, text))
    return rows


def key_at(image, row):
    start = image.offset(row)
    data = bytes(image.blob[start:start + 14])
    if data[:2] not in (b"\x48\x8d", b"\x4c\x8d"):
        raise EvidenceError("no lea at %#x" % row)
    return row + 7 + struct.unpack_from("<i", data, 3)[0]


def key_rows(image):
    rows = []
    for family, table in (("limits", LIMIT_KEYS), ("MainOrHip3", VARIANT_KEYS)):
        for load, pattern, lea, field, size, text in table:
            start = image.offset(load)
            wanted = bytes.fromhex(pattern)
            if bytes(image.blob[start:start + len(wanted)]) != wanted:
                raise EvidenceError("field row %#x" % load)
            at = key_at(image, lea)
            found = bytes(image.blob[image.offset(at):image.offset(at) + size])
            if found.decode() != text:
                raise EvidenceError("key at %#x" % lea)
            rows.append((family, "%#x" % load, pattern, "%#x" % lea, "%#x" % at, "%#x" % field, text))
    return rows


def serde_rows(image):
    blob = bytes(image.blob)
    rows = []
    for text in SERDE:
        at = blob.find(text)
        if at < 0:
            raise EvidenceError("no serde text")
        rows.append(("%#x" % at, text.decode()))
    return rows


def writer_rows():
    rows = []
    for copy in COPIES:
        for word in (WORD_TOTAL, WORD_SZ, WORD_TRANSFER, WORD_USERS):
            for offset in FIELDS[word]:
                rows.append((copy.name, word, "%#x" % copy.writers[word], "%#x" % (copy.defaults + offset), "%#x" % (LIMITS_AT + offset)))
    return rows


def arm_rows(image):
    rows = []
    for copy in COPIES:
        for word in WORDS:
            rows.append((copy.name, word, "%#x" % arm_of(image, copy.table, word - 0x12)))
    return rows


def past_head(rows):
    """Drop the shared dispatch head: all rows up to and including the first indirect jump."""
    for index, row in enumerate(rows):
        if row.op == "jmpi":
            return rows[index + 1:]
    raise EvidenceError("no dispatch jump")


def rows_of(image, target):
    return decode_range(image, *image.exact_fde(target))


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
            if not same(case, got, spec_run(case, before)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


COUNT_STEP = "same: +8 on the byte count ahead of the /0x2f0 parity step leaves the quotient and the loop test unchanged"
OLD_VALUE = "same: the replaced value goes back in rdx and the arm drops it"
FOUND_FLAG = "same: the found flag in eax is dropped by the arm"
HANDLE_WORD = "same: word of a vacant entry handle that the insert path never reads"
FULL_ROOT = "same: rdx is 0 on this row; the bound is live only for a full new root, which cannot happen"
COPY_PATH = "same: with the status test bent the copy path writes the same 0x186 tag word and the arm ends"
EXPECTED_SURVIVORS = {}
for _rows, _kind, _text in (
        ((0x235EAC9, 0x235ED19, 0x235F149, 0x4CBBBC9, 0x4CBC069, 0x4CBC2B9, 0x4CBC509, 0x4CBCB89, 0x4CBCFB9), "displacement", COUNT_STEP),
        ((0x285F617, 0x4938F17), "displacement", OLD_VALUE),
        ((0x285F621, 0x4938F21, 0x2866CEA, 0x494591A), "immediate", FOUND_FLAG),
        ((0x285F62B, 0x4938F2B, 0x285F6AA, 0x4938FAA), "immediate", HANDLE_WORD),
        ((0x285F66A, 0x4938F6A), "immediate", FULL_ROOT),
        ((0x2356454, 0x2356AC4, 0x235A7F2, 0x235C9F2, 0x4CAAD7A, 0x4CAB43B, 0x4CAF110, 0x4CB14F5, 0x4CB370A, 0x4CB3DCB, 0x4CB7AA0, 0x4CB9E85), "immediate", COPY_PATH)):
    for _row in _rows:
        EXPECTED_SURVIVORS[_row, _kind] = _text


def run_mutants(image, table, arm_table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    chosen = cases + vector_cases(240)
    reach = collections.defaultdict(list)
    for case in chosen:
        control.machine.seen = set()
        control.run(case)
        for va in control.machine.seen:
            reach[va].append(case)
    groups = [table[target] for target in TARGETS] + [arm_table[name] for name in sorted(arm_table)]
    for rows in groups:
        for va, kind, patch in edits_for(image, rows, seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            harness.machine.cache = {key: row for key, row in control.machine.cache.items() if not key <= va < key + row.size}
            hit = first_failure(harness, reach[va])
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results



def analyse(image, mutate=True, vectors=1200):
    RealCode.ALL = collect_real(image)
    harness = Harness(image)
    cases = base_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    cache = harness.machine.cache
    arms = {copy.name: sorted(va for va in seen if image.exact_fde(copy.dispatch)[0] <= va < image.exact_fde(copy.dispatch)[1]) for copy in COPIES}
    arm_table = {name: past_head([cache[va] for va in vas]) for name, vas in arms.items()}
    for rows in arm_table.values():
        for row in rows:
            row.data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, arm_table=arm_table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, texts=text_rows(image), keys=key_rows(image), serde=serde_rows(image), writers=writer_rows(), arms=arm_rows(image))
    if mutate:
        result["mutations"] = run_mutants(image, table, arm_table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def outcome_row(case, got):
    word = struct.unpack_from("<H", got[1])[0]
    return (COPIES[case.copy].name, case.word, case.name, "%#x" % word, hashlib.sha256(repr((got[1][:2], got[2], got[3])).encode()).hexdigest()[:16], len(got[4]))


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [(NAMES[target], "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("arm-rows.tsv", ("copy", "address", "size", "bytes", "operation"), [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in sorted(result["arm_table"]) for row in result["arm_table"][name]])
    tsv("writers.tsv", ("copy", "word", "writer", "default_offset", "row_offset"), result["writers"])
    tsv("arms.tsv", ("copy", "word", "arm"), result["arms"])
    tsv("keys.tsv", ("record", "field_row", "field_row_bytes", "key_row", "key_text_at", "field", "key"), result["keys"])
    tsv("texts.tsv", ("tag", "text"), result["texts"])
    tsv("serde.tsv", ("file_offset", "text"), result["serde"])
    tsv("outcomes.tsv", ("copy", "word", "case", "result", "digest", "events"), [outcome_row(case, got) for case, got in zip(result["cases"], result["outcomes"])])
    if "mutations" in result:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, k, o, d) for va, k, o, d in result["mutations"]])
    summary = {
        "binary": "artifacts/node/94/hl-node", "sha256": SHA256,
        "functions": {NAMES[target]: {"address": "%#x" % target, "bytes": sum(row.size for row in result["table"][target]), "instructions": len(result["table"][target]),
                                      "unreached_rows": ["%#x" % va for va in result["unreached"][target]]} for target in TARGETS},
        "arm_rows_reached": {name: len(rows) for name, rows in sorted(result["arm_table"].items())},
        "named_cases": len(result["cases"]), "vector_cases": result["vector_count"],
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

