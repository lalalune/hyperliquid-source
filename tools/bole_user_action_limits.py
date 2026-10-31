#!/usr/bin/env python3
"""Pin node #94 borrowLend: admission, two rate limit families and the spot room check around the BOLE core.

The real bytes run under recording stubs with real B-tree and hash table fixtures. A separately written rule list
predicts the heap, events and result of every run, and every reached conditional row, immediate and field offset is
mutated. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/bole_user_action_limits.py --out <dir>
"""

import argparse
import datetime
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


LIMIT = 0x37D9EF0
TIER = 0x373C9C0
REC_A = 0x1F84640
PROBE_A = 0x27C4B40
REC_B = 0x47D7550
CORE = 0x232BC70
TWO_ROLES = {0x28CC390: dict(rec=REC_A, map=0x770, total=0x7D0), 0x4592880: dict(rec=REC_B, map=0x11F0, total=0x1250), 0x4592950: dict(rec=REC_B, map=0x770, total=0x7D0)}
H_ROLES = {0x2764D60: dict(cls=0x2755400, rec=REC_A, direct=0x2732AE0, pre=0x272FE00, post=0x272D000, final=0x272F880, vault=0x8D0, map=0x770, total=0x7D0, fat_post=True),
           0x4D95A70: dict(cls=0x46F2FE0, rec=REC_B, direct=0x4D49EE0, pre=0x46EF9A0, post=0x46EF3D0, final=0x46EF720, vault=0x8D0, map=0x770, total=0x7D0, fat_post=False),
           0x4D96040: dict(cls=0x46F2E60, rec=REC_B, direct=0x4D44AE0, pre=0x46EFB70, post=0x46EF300, final=0x46EF4A0, vault=0x1350, map=0x11F0, total=0x1250, fat_post=False)}
D_ROLES = {0x2732AE0: dict(closure=0x25A8030, core=CORE, apply=0x2738E50, drop=0x28ABF00, vault=0x8D0),
           0x4D44AE0: dict(closure=0x4C23110, core=0x48CD030, apply=0x46F0EE0, drop=0x49A8520, vault=0x1350),
           0x4D49EE0: dict(closure=0x4C23110, core=0x48CD030, apply=0x46F0B20, drop=0x49A8520, vault=0x8D0)}
NAMES = {LIMIT: "window_limiter", TIER: "bole_two_tier_limit", REC_A: "abstraction_record", PROBE_A: "abstraction_record_probe", REC_B: "abstraction_record_inline", CORE: "bole_flags_and_spot_room",
         0x28CC390: "abstraction_limit", 0x4592880: "abstraction_limit_shifted", 0x4592950: "abstraction_limit_copy", 0x2764D60: "borrow_lend", 0x4D95A70: "borrow_lend_copy", 0x4D96040: "borrow_lend_shifted",
         0x2732AE0: "borrow_lend_apply", 0x4D44AE0: "borrow_lend_apply_shifted", 0x4D49EE0: "borrow_lend_apply_copy"}
TARGETS = tuple(sorted(NAMES))
RECORD_INNER = 0x28D7C10
HASH_A = 0x2840FB0
HASH_B = 0x473BF50
INSERT = 0x33BEAA0
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
SLOT_LIMIT = 0x5774748
SLOT_TIER = 0x5774D78
SLOT_DATE = 0x576E890
SLOT_UNWRAP = 0x576E470
SLOT_GROW = 0x57736F8
SLOT_SPOT_USER = 0x5773170
SLOT_ALLOC_FAIL = 0x576E128
LAZY_STATE = 0x5786380
DEFAULT_RECORD = 0x5786350
TAG_TEXT_TABLE = 0x59A8D0
INNER_TABLE = 0x5A56C4
INNER_ARM_10 = 0x3998418
OP_TABLE = 0x3EDF88
SELECT_TABLE = 0x3DCDF8
CLOSURE_TABLE = 0x3E79A0
MARK_BASE = 0x7700000000
OK = 0x186
TOP = MASK[8]
HEAP_FILL = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(0x2800))
OUT = HEAP_BASE + 0x100
USER_AT = HEAP_BASE + 0x300
ACTION = HEAP_BASE + 0x340
CLOSURE = HEAP_BASE + 0x380
ASSET_AT = HEAP_BASE + 0x3B0
OP_AT = HEAP_BASE + 0x3B8
AMOUNT_AT = HEAP_BASE + 0x3C0
CLASS_REC = HEAP_BASE + 0x400
SPOT_REC = HEAP_BASE + 0x480
REC_AT = HEAP_BASE + 0x500
TIME_AT = HEAP_BASE + 0x580
LREC = HEAP_BASE + 0x5A0
INSERT_NODE = HEAP_BASE + 0x600
S = HEAP_BASE + 0x1000
B = S + 0x498
NODES = HEAP_BASE + 0x2800
BUCKETS = 64
CTRL = HEAP_BASE + 0xC000
USED = 0xD000
USER = 0x1234567890ABCDEF0011223344556677889900AA
DECOY = int("AB" * 20, 16)
ROUTE_HASH = (0x5B << 57) | 0x1234567000 | 11


class Layout:
    def __init__(self, size, val_at, val_size, key_at, len_at, edge_at, parent_idx=None):
        self.size, self.val_at, self.val_size, self.key_at, self.len_at, self.edge_at, self.parent_idx = size, val_at, val_size, key_at, len_at, edge_at, parent_idx


L_RESERVE = Layout(0x860, 0, 0xB0, 0x798, 0x7F2, 0x7F8)
L_BALANCE = Layout(0x1E0, 0x60, 0x18, 8, 0x16A, 0x170)
L_USER_REC = Layout(0x358, 0, 0x30, 0x218, 0x2F6, 0x2F8)
L_VAULT = Layout(0x8D8, 0, 0xB0, 0x798, 0x876, 0x878)


def wrap32(value):
    value &= MASK[4]
    return value - (1 << 32) if value >> 31 else value


def lock_millis(date, secs, frac):
    """Year, ordinal and flags in one signed word, then seconds and nanoseconds, to Unix milliseconds floored at 0."""
    date = wrap32(date)
    year = date >> 13
    y, shift = year - 1, 0
    if year <= 0:
        k = (1 - year) // 400 + 1
        y += 400 * k
        shift = -146097 * k
    days = ((date >> 4) & 0x1FF) + shift + (wrap32(y * 1461) >> 2) - y // 100 + (y // 100 >> 2) - 719163
    ms = (days * 86400 + (secs & MASK[4])) * 1000 + (frac & MASK[4]) // 10 ** 6
    ms = ms & TOP
    return 0 if ms == 0 or ms >> 63 else ms



def day(year, month, dayofmonth):
    """Date word: year << 13 | ordinal << 4 | flags (flags are ignored by every reader here)."""
    start = datetime.date(year, 1, 1)
    return (year << 13) | ((datetime.date(year, month, dayofmonth) - start).days + 1) << 4 | 3


NOW = (day(2026, 10, 31), 50400, 5000000)
EPOCH = day(1970, 1, 1)


class Case:
    DEFAULTS = dict(entry=LIMIT, user=USER, now=NOW, epoch=EPOCH, op=1, asset=5, w0=1, w1=1000, cls=0, f5b0=1, f5b1=0, asset_shape="leaf", vault_shape="absent", vault_flag=1, vault_word=0,
                    u_shape="leaf", urec=(0, EPOCH, 0, 0), uw=60000, ul=10, grec=(0, EPOCH, 0, 0), gw=60000, gl=10,
                    w1p=86400000, l1=5, w2p=3600000, l2=5, rec1=(0, EPOCH, 0, 0), rec2=(0, EPOCH, 0, 0), usage=0, total=0,
                    rec=(0, EPOCH, 0, 0), window=1000, limit=10, d_tag=OK, post_tag=OK,
                    sel=None, avail=0x77, a=1, b=0, c=0, flag=0, core_tag=0, core_byte=0x11, changed=500, inc=1, bal_shape="leaf", bal=(10 ** 6, 0, 0x33), lock=3, apply=0x11,
                    table=(), grow_left=5, items=7, hash=ROUTE_HASH)

    def __init__(self, name, **fields):
        self.name = name
        for key, value in self.DEFAULTS.items():
            setattr(self, key, fields.pop(key, value))
        if fields:
            raise EvidenceError("unknown case fields: %s" % sorted(fields))
        if self.sel is None:
            self.sel = self.op
        self.addr = {}


class Fault(Exception):
    pass


def u64le(*words):
    return b"".join(word.to_bytes(8, "little") for word in words)


def stamp(now):
    return struct.pack("<III", now[0] & MASK[4], now[1] & MASK[4], now[2] & MASK[4])


def rec_bytes(rec):
    return rec[0].to_bytes(8, "little") + stamp(rec[1:])


def default_record(date):
    return bytes(8) + stamp((date, 0, 0)) + bytes([STACK_MARK]) * 4 + bytes(8) + bytes([STACK_MARK]) * 8 + bytes(8)


def sat_up(value):
    return min(value + 1, TOP)


def core_image(case):
    data = bytearray((index * 3 + 1) & 0xFF for index in range(0x120))
    data[0:8] = case.core_tag.to_bytes(8, "little")
    data[8] = case.core_byte
    data[0x100:0x108] = case.changed.to_bytes(8, "little")
    data[0x108] = case.inc
    return bytes(data)


def d_image(case):
    data = bytearray((index * 5 + 2) & 0xFF for index in range(0x60))
    data[0:2] = case.d_tag.to_bytes(2, "little")
    return bytes(data)


def spec_run(case, before):
    heap = bytearray(before)
    events = []

    def poke(addr, data):
        heap[addr - HEAP_BASE:addr - HEAP_BASE + len(data)] = data

    def word(addr, size=8):
        return int.from_bytes(heap[addr - HEAP_BASE:addr - HEAP_BASE + size], "little")

    def done(label):
        return ("run", bytes(heap), [], tuple(events), None, label)

    def limiter(at, now, window, limit):
        count = word(at)
        old = lock_millis(word(at + 8, 4), word(at + 12, 4), word(at + 16, 4))
        new = lock_millis(*now)
        if window == 0:
            raise Fault("window zero")
        count = 1 if old // window < new // window else sat_up(count)
        poke(at, count.to_bytes(8, "little") + stamp(now))
        return count <= limit

    def tier(now):
        address = case.addr["user_value"]
        if address is None:
            if case.epoch == 0:
                raise Panicked("unwrap")
            index = case.addr["insert_index"]
            address = INSERT_NODE + 0x30 * index
            poke(address, default_record(case.epoch))
            events.append(("insert",))
        if not limiter(address, now, case.uw, case.ul):
            return 7
        return 10 if limiter(B + 0x90, now, case.gw, case.gl) else 7

    def two(role, now):
        events.append(("rec", S + role["map"]))
        first = limiter(REC_AT, now, case.w1p, case.l1)
        second = limiter(REC_AT + 0x18, now, case.w2p, case.l2)
        if not (first or second):
            return False
        poke(REC_AT + 0x30, sat_up(word(REC_AT + 0x30)).to_bytes(8, "little"))
        poke(S + role["total"], sat_up(word(S + role["total"])).to_bytes(8, "little"))
        return True

    entry = case.entry
    try:
        if entry == LIMIT:
            passed = limiter(LREC, case.now, case.window, case.limit)
            return ("value", bytes(heap), [], (), int(passed), "pass" if passed else "over")
        if entry in TWO_ROLES:
            passed = two(TWO_ROLES[entry], case.now)
            poke(OUT, (OK if passed else 0x170).to_bytes(2, "little"))
            return done("ok" if passed else "0x170")
        if entry == TIER:
            value = tier(case.now)
            return ("value", bytes(heap), [], tuple(events), value, "tier %d" % value)
        if entry in (REC_A, REC_B):
            return spec_record(case, heap, events)
        if entry == CORE:
            return spec_core(case, heap, events, poke, word)
        if entry in D_ROLES:
            return spec_direct(case, heap, events, poke, word)
        role = H_ROLES[entry]
        events.append(("class",))
        if case.cls >= 4 and not case.f5b0:
            poke(OUT, (0x173).to_bytes(2, "little"))
            return done("0x173")
        value = tier(case.now)
        if value != 10:
            poke(OUT, (0xE1).to_bytes(2, "little") + bytes([value]))
            return done("0xe1 %d" % value)
        if case.asset_shape not in ("leaf", "deep"):
            poke(OUT, (0xE1).to_bytes(2, "little") + bytes([0]))
            return done("0xe1 0")
        if case.vault_shape in ("leaf", "deep", "deep left"):
            if case.op in (0, 2) or case.asset != 0 or case.vault_flag == 0:
                poke(OUT, (0x15).to_bytes(2, "little"))
                return done("0x15")
        events.append(("class",))
        routed = case.cls == 3 and not case.f5b1 or case.cls > 3 and not case.f5b0
        if routed:
            if not two(role, case.now):
                poke(OUT, (0x170).to_bytes(2, "little"))
                return done("0x170")
            events.append(("pre", case.asset))
        events.append(("direct", case.asset, case.op, case.w0, case.w1))
        if routed:
            events.append(("post", case.asset))
            if role["fat_post"] and case.post_tag != OK:
                events.append(("post drop",))
        if case.d_tag == OK:
            poke(OUT, OK.to_bytes(2, "little"))
            return done("ok")
        poke(OUT, d_image(case))
        return done("direct %#x" % case.d_tag)
    except Fault as fault:
        return ("fault", str(fault), [], tuple(events), None, "fault")
    except Panicked as panic:
        return ("panic", str(panic), [], tuple(events), None, "panic")


def spec_record(case, heap, events):
    def get(addr, size=1):
        return int.from_bytes(heap[addr - HEAP_BASE:addr - HEAP_BASE + size], "little")

    def poke(addr, data):
        heap[addr - HEAP_BASE:addr - HEAP_BASE + len(data)] = data

    mask = BUCKETS - 1
    h2 = case.hash >> 57
    key = case.user.to_bytes(20, "big")
    events.append(("hash",))
    pos, step = case.hash & mask, 0
    while True:
        group = [get(CTRL + pos + index) for index in range(16)]
        for index, byte in enumerate(group):
            if byte == h2:
                slot = (pos + index) & mask
                at = CTRL - 0xE0 * (slot + 1)
                if bytes(heap[at - HEAP_BASE:at - HEAP_BASE + 20]) == key:
                    return ("value", bytes(heap), [], tuple(events), at + 0x18, "hit")
        if 0xFF in group:
            break
        step += 16
        pos = (pos + step) & mask
    table = S + 0x770
    if get(table + 0x10, 8) == 0:
        events.append(("grow",))
    if case.epoch == 0:
        return ("panic", "unwrap", [], tuple(events), None, "panic")
    pos, step = case.hash & mask, 0
    while True:
        group = [get(CTRL + pos + index) for index in range(16)]
        free = [index for index, byte in enumerate(group) if byte & 0x80]
        if free:
            break
        step += 16
        pos = (pos + step) & mask
    slot = (pos + free[0]) & mask
    byte = get(CTRL + slot)
    if not byte & 0x80:
        slot = next(index for index in range(16) if get(CTRL + index) & 0x80)
        byte = get(CTRL + slot)
    poke(CTRL + slot, bytes([h2]))
    poke(CTRL + (((slot - 16) & mask) + 16), bytes([h2]))
    poke(table + 0x10, ((get(table + 0x10, 8) - (byte & 1)) & TOP).to_bytes(8, "little"))
    poke(table + 0x18, ((get(table + 0x18, 8) + 1) & TOP).to_bytes(8, "little"))
    at = CTRL - 0xE0 * (slot + 1)
    poke(at, key)
    poke(at + 0x18, rec_bytes((0, case.epoch, 0, 0)))
    poke(at + 0x30, rec_bytes((0, case.epoch, 0, 0)))
    poke(at + 0x44, bytes([STACK_MARK]) * 4 + bytes(0x98))
    return ("value", bytes(heap), [], tuple(events), at + 0x18, "insert")


def spec_core(case, heap, events, poke, word):
    def status(byte):
        poke(OUT + 8, bytes([byte]))
        poke(OUT, (3).to_bytes(8, "little"))
        return ("run", bytes(heap), [], tuple(events), None, "inner %d" % byte)

    sel = case.sel
    if sel == 0:
        if not case.a or case.c:
            return status(8)
        if case.b:
            return status(4)
    elif sel in (1, 2):
        if not case.a:
            return status(8)
    elif not case.a or case.c:
        return status(8)
    user_at = case.addr["user_value"]
    events.append(("core", user_at if user_at is not None else DEFAULT_RECORD, sel, case.avail, case.w0, case.w1, case.flag, case.asset))
    if case.core_tag == 3:
        return status(case.core_byte)
    image = core_image(case)[:0x110]
    if case.core_tag != 2 and case.inc:
        total, hold = case.bal[:2] if case.bal_shape in ("leaf", "deep") else (0, 0)
        events.append(("spot",))
        if case.changed + hold > TOP or case.changed + hold > total:
            events.append(("drop",))
            return status(0xA)
    poke(OUT, image)
    return ("run", bytes(heap), [], tuple(events), None, "tag %d" % case.core_tag)


def spec_direct(case, heap, events, poke, word):
    locked = S + 0x58
    poke(locked, sat_up(case.lock).to_bytes(8, "little"))

    def finish(label):
        count = word(locked)
        poke(locked, (count - 1 if count else 0).to_bytes(8, "little"))
        return ("run", bytes(heap), [], tuple(events), None, label)

    if case.w0 & 1 and case.w1 == 0:
        poke(OUT, OK.to_bytes(2, "little"))
        return finish("no change")
    flag = int(case.vault_shape in ("leaf", "deep", "deep left") and case.vault_word == 1)
    events.append(("closure", case.op))
    events.append(("core", case.sel, case.avail, case.w0, case.w1, flag, case.asset))
    if case.core_tag == 3:
        poke(OUT, (0xE1).to_bytes(2, "little") + bytes([case.core_byte]))
        return finish("0xe1 %d" % case.core_byte)
    if case.core_tag == 2:
        poke(OUT, (0xE2).to_bytes(2, "little"))
        return finish("0xe2 tag")
    if case.changed == 0:
        poke(OUT, (0xE2).to_bytes(2, "little"))
        events.append(("drop",))
        return finish("0xe2 zero")
    events.append(("apply", case.asset, case.op, case.changed))
    if case.apply == 0x11:
        poke(OUT, OK.to_bytes(2, "little"))
        return finish("ok")
    poke(OUT, (0xE1).to_bytes(2, "little") + bytes([0xA]))
    return finish("0xe1 10")


class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        memory = machine.memory
        statics = memory.statics
        calls = {HASH_A: self.on_hash, HASH_B: self.on_hash, INSERT: self.on_insert, RECORD_INNER: self.on_core, 0x48CD030: self.on_core}
        for role in H_ROLES.values():
            calls[role["cls"]] = self.on_class
            calls[role["pre"]] = self.on_pre
            calls[role["post"]] = self.on_post if role["fat_post"] else self.on_post_thin
            calls[role["final"]] = self.on_final
        calls[0x277EBA0] = self.on_post_drop
        machine.calls = calls
        self.direct_calls = {role["direct"]: self.on_direct for role in H_ROLES.values()}
        self.record_calls = {REC_A: self.on_record, REC_B: self.on_record}
        self.closure_calls = {}
        for role in D_ROLES.values():
            self.closure_calls[role["closure"]] = self.on_closure
            self.closure_calls[role["apply"]] = self.on_apply
            self.closure_calls[role["drop"]] = self.on_drop
            if role["core"] != CORE:
                self.closure_calls[role["core"]] = self.on_core_d
        self.closure_calls[CORE] = self.on_core_d
        hooks = {SLOT_MEMCMP: self.on_memcmp, SLOT_MEMCPY: self.on_memcpy, SLOT_DATE: self.on_date, SLOT_UNWRAP: self.on_unwrap, SLOT_GROW: self.on_grow, SLOT_SPOT_USER: self.on_spot_user, SLOT_ALLOC_FAIL: self.on_unwrap}
        for slot, hook in hooks.items():
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        statics[SLOT_LIMIT] = LIMIT
        statics[SLOT_TIER] = TIER
        statics[LAZY_STATE] = 0
        machine.real = frozenset((LIMIT, TIER))
        self.case = None
        self.events = []
        self.node_cur = NODES

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def user_at(self, address):
        self.expect(self.machine.memory.bytes_at(address, 20) == self.case.user.to_bytes(20, "big"), "user bytes")

    def on_memcmp(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 20, "memcmp length")
        left = machine.memory.bytes_at(regs[RDI], 20)
        right = machine.memory.bytes_at(regs[RSI], 20)
        regs[RAX] = 0 if left == right else 0x7 if left > right else (-5) & MASK[4]

    def on_memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_date(self, machine):
        self.expect(machine.regs[RDI] & MASK[4] == 0xAF93B, "day number")
        machine.regs[RAX] = self.case.epoch

    def on_unwrap(self, machine):
        raise Panicked("unwrap")

    def on_grow(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == 1 and regs[RCX] == 1 and regs[RDI] == S + 0x770 and regs[RDX] == S + 0x790, "grow arguments")
        self.events.append(("grow",))

    def on_hash(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == S + 0x790, "hash state")
        self.user_at(regs[RSI])
        regs[RAX] = self.case.hash
        self.events.append(("hash",))

    def on_class(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == S, "class state")
        self.user_at(regs[RSI])
        regs[RAX] = CLASS_REC
        self.events.append(("class",))

    def on_record(self, machine):
        regs = machine.regs
        self.user_at(regs[RSI])
        regs[RAX] = REC_AT
        self.events.append(("rec", regs[RDI]))

    def arg(self, index):
        return self.machine.memory.read(self.machine.regs[RSP] + 8 * index, 8)

    def on_pre(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RDI] == S and regs[RDX] == case.asset and regs[RCX] == 0 and regs[R8] == case.asset, "pre arguments")
        self.user_at(regs[RSI])
        self.expect(machine.memory.read(regs[R9], 8) == 4, "pre word")
        self.expect(self.arg(1) & MASK[4] == 0, "pre flag")
        self.events.append(("pre", case.asset))

    def on_post(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RSI] == S and regs[RCX] == case.asset and regs[R8] == 0 and regs[R9] == case.asset, "post arguments")
        self.user_at(regs[RDX])
        self.expect(self.arg(1) == 0 and self.arg(3) == 0, "post words")
        machine.memory.write(regs[RDI], 2, case.post_tag)
        self.events.append(("post", case.asset))

    def on_post_drop(self, machine):
        self.events.append(("post drop",))

    def on_post_thin(self, machine):
        regs = machine.regs
        case = self.case
        self.expect(regs[RDI] == S and regs[RDX] == case.asset and regs[RCX] == 0 and regs[R8] == case.asset and regs[R9] == 0, "post arguments")
        self.user_at(regs[RSI])
        self.expect(self.arg(2) == 0, "post word")
        self.events.append(("post", case.asset))

    def on_final(self, machine):
        raise Halt("final call reached")

    def on_direct(self, machine):
        regs = machine.regs
        case = self.case
        memory = machine.memory
        self.expect(regs[RDX] == S, "direct state")
        closure = regs[RSI]
        self.expect(memory.read(closure, 8) == USER_AT, "closure user")
        asset = memory.read(memory.read(closure + 8, 8), 8)
        op = memory.read(memory.read(closure + 0x10, 8), 1)
        amount = memory.read(closure + 0x18, 8)
        self.events.append(("direct", asset, op, memory.read(amount, 8), memory.read(amount + 8, 8)))
        memory.put_bytes(regs[RDI], d_image(case))

    def on_closure(self, machine):
        regs = machine.regs
        memory = machine.memory
        case = self.case
        self.expect(regs[RDI] & 0xFF == case.op, "closure op")
        env = regs[RSI]
        self.expect(memory.read(env, 8) == S + 0x80, "closure spot")
        self.user_at(memory.read(env + 8, 8))
        self.expect(memory.read(memory.read(env + 0x10, 8), 8) == case.asset, "closure asset")
        regs[RAX], regs[RDX] = case.sel, case.avail
        machine.keep_rdx = True
        self.events.append(("closure", case.op))

    def on_core_d(self, machine):
        regs = machine.regs
        memory = machine.memory
        case = self.case
        self.expect(regs[RSI] == B, "core state")
        self.user_at(regs[RDX])
        self.expect(memory.bytes_at(self.arg(4), 12) == stamp(case.now), "core time")
        self.expect(self.arg(5) == S + 0x80, "core spot")
        self.events.append(("core", regs[R8], regs[R9], self.arg(1), self.arg(2), self.arg(3) & 0xFF, regs[RCX]))
        memory.put_bytes(regs[RDI], core_image(case)[:0x110])

    def on_core(self, machine):
        regs = machine.regs
        memory = machine.memory
        case = self.case
        args = regs[RDX]
        self.expect(memory.read(args + 0x68 - 0x48 + 0, 8) == B + 0xC8, "args state")
        self.expect(memory.read(args + 0x28, 8) == S + 0x90, "args token")
        self.expect(memory.bytes_at(args + 0x38, 12) == stamp(case.now), "args time")
        self.expect(memory.bytes_at(args + 0x44, 20) == case.user.to_bytes(20, "big"), "args user")
        self.expect(memory.read(args + 0x58, 1) == case.flag, "args flag")
        self.expect(memory.read(args + 0x30, 8) == case.asset, "args asset")
        self.events.append(("core", regs[RSI], memory.read(args + 0x10, 8), memory.read(args + 0x18, 8), memory.read(args, 8), memory.read(args + 8, 8), case.flag, case.asset))
        memory.put_bytes(regs[RDI], core_image(case)[:0x110])

    def on_spot_user(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == S + 0x80, "spot state")
        self.user_at(regs[RSI])
        regs[RAX] = SPOT_REC
        self.events.append(("spot",))

    def on_apply(self, machine):
        regs = machine.regs
        case = self.case
        memory = machine.memory
        self.expect(regs[RDI] == S and regs[RDX] == case.asset and regs[RCX] & 0xFF == case.op and regs[R9] == 1, "apply arguments")
        self.user_at(regs[RSI])
        at = regs[R8]
        self.expect(memory.read(at, 8) == case.core_tag and memory.read(at + 8, 1) == case.core_byte and memory.bytes_at(at + 9, 0xF7) == core_image(case)[9:0x100], "apply record")
        self.events.append(("apply", case.asset, case.op, memory.read(at + 0x100, 8)))
        regs[RAX] = case.apply

    def on_drop(self, machine):
        self.events.append(("drop",))

    def on_insert(self, machine):
        regs = machine.regs
        memory = machine.memory
        ctx = regs[RSI]
        case = self.case
        self.expect(memory.read(ctx, 8) == B + 0x100, "insert root")
        self.expect(memory.bytes_at(ctx + 0x20, 20) == case.user.to_bytes(20, "big"), "insert key")
        self.expect(memory.read(ctx + 8, 8) == case.addr["leaf"], "insert leaf")
        self.expect(memory.read(ctx + 0x10, 8) == 0, "insert height")
        if case.addr["leaf"]:
            self.expect(memory.read(ctx + 0x18, 8) == case.addr["insert_index"], "insert index")
        index = case.addr["insert_index"]
        memory.copy(INSERT_NODE + 0x30 * index, regs[RDX], 0x30)
        memory.write(regs[RDI], 8, INSERT_NODE)
        memory.write(regs[RDI] + 0x10, 8, index)
        self.events.append(("insert",))

    def alloc_node(self, layout):
        at = self.node_cur
        self.node_cur += layout.size
        memory = self.machine.memory
        memory.put_bytes(at, bytes((0x31 + 7 * index) & 0xFF for index in range(layout.size)))
        return at

    def u64_node(self, layout, items, children=(), stale=None):
        at = self.alloc_node(layout)
        memory = self.machine.memory
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            key = stale if stale is not None and slot >= len(items) else 0x5A5A0000 + slot
            memory.write(at + layout.key_at + 8 * slot, 8, key)
        for slot, (key, value) in enumerate(items):
            memory.write(at + layout.key_at + 8 * slot, 8, key)
            for index, word in enumerate(value):
                memory.write(at + layout.val_at + layout.val_size * slot + 8 * index, 8, word)
        for slot, child in enumerate(children):
            memory.write(at + layout.edge_at + 8 * slot, 8, child)
        return at

    def u64_tree(self, layout, shape, key, value, decoy, head):
        """Write root and height at `head`. Unused key slots hold the searched key, so a length bound error finds it."""
        memory = self.machine.memory
        if shape == "empty":
            memory.write(head, 8, 0)
            memory.write(head + 8, 8, 0xFEED)
            return
        if shape == "deep":
            left = self.u64_node(layout, [(key - 2 & TOP, decoy), (key - 1 & TOP, decoy)], stale=key)
            right = self.u64_node(layout, [(key, value), (key + 2, decoy)], stale=key + 1)
            root = self.u64_node(layout, [(key - 1 & TOP, decoy)], (left, right))
            memory.write(head, 8, root)
            memory.write(head + 8, 8, 1)
            return
        if shape == "leaf":
            lows = [(key - 3 + index & TOP, decoy) for index in range(3)] if key >= 3 else []
            root = self.u64_node(layout, lows + [(key, value), (key + 1, decoy)], stale=key)
        elif shape == "miss":
            root = self.u64_node(layout, [(key - 1 & TOP, decoy), (key + 1, decoy)], stale=key)
        else:
            root = self.u64_node(layout, [(key - 1 & TOP, decoy)], stale=key)
        memory.write(head, 8, root)
        memory.write(head + 8, 8, 0)

    def addr_node(self, layout, items, children=(), stale=None):
        at = self.alloc_node(layout)
        memory = self.machine.memory
        memory.write(at + layout.len_at, 2, len(items))
        for slot in range(11):
            key = stale if stale is not None and slot >= len(items) else 0xFFFFFF00 + slot
            memory.put_bytes(at + layout.key_at + 20 * slot, key.to_bytes(20, "big"))
        for slot, (key, value) in enumerate(items):
            memory.put_bytes(at + layout.key_at + 20 * slot, key.to_bytes(20, "big"))
            memory.put_bytes(at + layout.val_at + layout.val_size * slot, value)
        for slot, child in enumerate(children):
            memory.write(at + layout.edge_at + 8 * slot, 8, child)
            if layout.parent_idx is not None:
                memory.write(child, 8, at)
                memory.write(child + layout.parent_idx, 2, slot)
        return at

    def addr_tree(self, layout, shape, key, value, decoy, head):
        memory = self.machine.memory
        if shape == "empty":
            memory.write(head, 8, 0)
            memory.write(head + 8, 8, 0xFEED)
            return
        if shape == "deep":
            left = self.addr_node(layout, [(key - 2, decoy), (key - 1, decoy)], stale=key)
            right = self.addr_node(layout, [(key, value), (key + 2, decoy)], stale=key + 1)
            root = self.addr_node(layout, [(key - 1, decoy)], (left, right))
            memory.write(head, 8, root)
            memory.write(head + 8, 8, 1)
            return
        if shape == "deep left":
            left = self.addr_node(layout, [(key - 1, decoy), (key, value)], stale=key + 1)
            right = self.addr_node(layout, [(key + 2, decoy)], stale=key)
            root = self.addr_node(layout, [(key + 1, decoy)], (left, right))
            memory.write(head, 8, root)
            memory.write(head + 8, 8, 1)
            return
        if shape == "leaf":
            root = self.addr_node(layout, [(key - 3 + index, decoy) for index in range(3)] + [(key, value), (key + 1, decoy)], stale=key)
        elif shape == "miss":
            root = self.addr_node(layout, [(key - 1, decoy), (key + 1, decoy)], stale=key)
        else:
            root = self.addr_node(layout, [(key - 1, decoy)], stale=key)
        memory.write(head, 8, root)
        memory.write(head + 8, 8, 0)

    def asset_tree(self, case):
        record = bytes(0xB0)
        self.u64_tree(L_RESERVE, case.asset_shape, case.asset, (0x77,) * 22, (0x88,) * 22, S + 0x568)

    def vault_tree(self, case, offset):
        memory = self.machine.memory
        head = S + offset
        if case.vault_shape == "absent":
            memory.write(head, 8, 0)
            memory.write(head + 8, 8, 0xFEED)
            return
        value = bytearray(b"\x5A" * 0xB0)
        decoy = bytearray(b"\xC3" * 0xB0)
        value[0:4] = struct.pack("<I", case.vault_word)
        decoy[0:4] = struct.pack("<I", 0 if case.vault_word == 1 else 1)
        value[0xAF] = case.vault_flag
        decoy[0xAF] = 0 if case.vault_flag else 1
        self.addr_tree(L_VAULT, case.vault_shape, case.user, bytes(value), bytes(decoy), head)

    def user_tree(self, case):
        """The S+0x598 tree: record value address of the user, or the leaf and slot of an insert."""
        memory = self.machine.memory
        head = B + 0x100
        value = rec_bytes(case.urec) + bytes([0x41]) * 4 + bytes([0x42]) * 24
        decoy = rec_bytes((0x999, NOW[0], 1, 2)) + bytes([0x51]) * 28
        self.addr_tree(L_USER_REC, case.u_shape, case.user, value, decoy, head)
        root = memory.read(head, 8)
        addr = case.addr
        addr["user_value"] = None
        addr["leaf"] = 0
        addr["insert_index"] = 0
        if case.u_shape == "empty":
            return
        height = memory.read(head + 8, 8)
        if height:
            right = memory.read(root + L_USER_REC.edge_at + 8, 8)
            left = memory.read(root + L_USER_REC.edge_at, 8)
            node = right if case.u_shape == "deep" else left
        else:
            node = root
        count = memory.read(node + L_USER_REC.len_at, 2)
        for slot in range(count):
            key = int.from_bytes(memory.bytes_at(node + L_USER_REC.key_at + 20 * slot, 20), "big")
            if key == case.user:
                addr["user_value"] = node + 0x30 * slot
                return
            if key > case.user:
                addr["leaf"], addr["insert_index"] = node, slot
                return
        addr["leaf"], addr["insert_index"] = node, count

    def table_state(self, case):
        memory = self.machine.memory
        table = S + 0x770
        memory.write(table, 8, CTRL)
        memory.write(table + 8, 8, BUCKETS - 1)
        memory.write(table + 0x10, 8, case.grow_left)
        memory.write(table + 0x18, 8, case.items)
        memory.put_bytes(CTRL, bytes([0xFF]) * (BUCKETS + 16))
        memory.put_bytes(CTRL - 0xE0 * BUCKETS, bytes((index * 7 + 3) & 0xFF or 1 for index in range(0xE0 * BUCKETS)))

        def set_ctrl(slot, byte):
            memory.write(CTRL + slot, 1, byte)
            memory.write(CTRL + (((slot - 16) & (BUCKETS - 1)) + 16), 1, byte)

        for slot, byte, key in case.table:
            set_ctrl(slot, byte)
            if key is not None:
                memory.put_bytes(CTRL - 0xE0 * (slot + 1), key.to_bytes(20, "big"))

    def fresh(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [POISON | POISON << 64] * 16
        memory.put_bytes(HEAP_BASE, HEAP_FILL)
        self.case, self.events, self.node_cur = case, [], NODES
        case.addr = {}
        memory.put_bytes(USER_AT, case.user.to_bytes(20, "big"))
        memory.put_bytes(S + 0x60, stamp(case.now))
        memory.put_bytes(TIME_AT, stamp(case.now))
        memory.write(CLASS_REC + 0x3C, 1, case.cls)
        memory.write(S + 0x5B0, 1, case.f5b0)
        memory.write(S + 0x5B8, 1, 0)
        memory.write(S + 0x5B1, 1, case.f5b1)
        memory.write(S + 0x5B2, 1, case.b)
        memory.write(S + 0x5B3, 1, case.a)
        memory.write(S + 0x5B4, 1, case.c)
        for offset, value in ((0x4E8, case.w1p), (0x4F0, case.l1), (0x4F8, case.w2p), (0x500, case.l2), (0x508, case.gw), (0x510, case.gl), (0x518, case.uw), (0x520, case.ul)):
            memory.write(S + offset, 8, value)
        memory.put_bytes(B + 0x90, rec_bytes(case.grec))
        memory.write(S + 0x58, 8, case.lock)
        memory.put_bytes(REC_AT, rec_bytes(case.rec1))
        memory.put_bytes(REC_AT + 0x18, rec_bytes(case.rec2))
        memory.write(REC_AT + 0x30, 8, case.usage)
        memory.write(S + 0x7D0, 8, case.total)
        memory.write(S + 0x1250, 8, case.total)
        memory.put_bytes(LREC, rec_bytes(case.rec))
        entry = case.entry
        if entry == TIER or entry in H_ROLES:
            self.user_tree(case)
        if entry == CORE:
            self.user_tree(case)
            self.u64_tree(L_BALANCE, case.bal_shape, case.asset, case.bal, tuple(word ^ 0x5555 for word in case.bal), SPOT_REC + 0x10)
            if case.bal_shape == "short":
                # The searched key sits stale in slot 1, so a wrong length bound finds a row with room.
                root = memory.read(SPOT_REC + 0x10, 8)
                memory.write(root + L_BALANCE.val_at + L_BALANCE.val_size, 8, TOP)
                memory.write(root + L_BALANCE.val_at + L_BALANCE.val_size + 8, 8, 0)
        if entry in H_ROLES:
            self.asset_tree(case)
            self.vault_tree(case, H_ROLES[entry]["vault"])
            memory.put_bytes(ACTION, u64le(case.w0, case.w1, case.asset) + bytes([case.op]))
        if entry in D_ROLES:
            self.vault_tree(case, D_ROLES[entry]["vault"])
            memory.write(ASSET_AT, 8, case.asset)
            memory.write(OP_AT, 1, case.op)
            memory.put_bytes(AMOUNT_AT, u64le(case.w0, case.w1))
            for index, value in enumerate((USER_AT, ASSET_AT, OP_AT, AMOUNT_AT)):
                memory.write(CLOSURE + 8 * index, 8, value)
        if entry in (REC_A, REC_B):
            self.table_state(case)
        self.select_calls(entry)
        return bytes(memory.heap[:USED])

    def select_calls(self, entry):
        machine = self.machine
        calls = dict(machine.calls)
        calls.update(self.closure_calls)
        if entry in H_ROLES or entry in TWO_ROLES:
            calls.update(self.direct_calls)
            calls.update(self.record_calls)
        if entry == CORE:
            calls[RECORD_INNER] = self.on_core
            real = (LIMIT, TIER, PROBE_A)
        else:
            real = (LIMIT, TIER, PROBE_A, entry) if entry in (REC_A, REC_B) else (LIMIT, TIER, PROBE_A)
        machine.calls = calls
        machine.real = frozenset(real)

    def run(self, case):
        before = self.fresh(case)
        machine = self.machine
        entry = case.entry
        try:
            if entry == LIMIT:
                value = machine.run(LIMIT, {RDI: LREC, RSI: TIME_AT, RDX: case.window, RCX: case.limit})
                return before, ("value", bytes(machine.memory.heap[:USED]), [], tuple(self.events), value & 0xFF, None)
            if entry == TIER:
                value = machine.run(TIER, {RDI: B, RSI: USER_AT, RDX: TIME_AT})
                return before, ("value", bytes(machine.memory.heap[:USED]), [], tuple(self.events), value & 0xFF, None)
            if entry in (REC_A, REC_B):
                value = machine.run(entry, {RDI: S + 0x770, RSI: USER_AT})
                return before, ("value", bytes(machine.memory.heap[:USED]), [], tuple(self.events), value, None)
            if entry in TWO_ROLES:
                machine.run(entry, {RDI: OUT, RSI: USER_AT, RDX: S})
            elif entry == CORE:
                memory = machine.memory
                for index, word in enumerate((case.w0, case.w1, case.flag, TIME_AT, S + 0x80)):
                    memory.write(STACK_TOP - 0x100 + 8 * index, 8, word)
                machine.run(CORE, {RDI: OUT, RSI: B, RDX: USER_AT, RCX: case.asset, R8: case.sel, R9: case.avail})
            elif entry in D_ROLES:
                machine.run(entry, {RDI: OUT, RSI: CLOSURE, RDX: S})
            else:
                machine.run(entry, {RDI: OUT, RSI: S, RDX: USER_AT, RCX: ACTION})
        except Halt as halt:
            if "division by zero" in str(halt):
                return before, ("fault", "window zero", [], tuple(self.events), None, None)
            raise
        except Panicked as panic:
            return before, ("panic", str(panic), [], tuple(self.events), None, None)
        if entry in H_ROLES and machine.memory.read(OUT, 2) == 0x170:
            # The refusal goes through the shared copy-out, so a stale stack tail lands behind the tag.
            machine.memory.put_bytes(OUT + 2, before[OUT - HEAP_BASE + 2:OUT - HEAP_BASE + 0x60])
        return before, ("run", bytes(machine.memory.heap[:USED]), [], tuple(self.events), None, None)



def same(got, want):
    return got[:5] == want[:5]


def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & TOP
        yield state


def time_of(ms):
    """(date word, seconds, nanoseconds) for a Unix millisecond value at or after 1970."""
    days, rest = divmod(ms, 86400000)
    date = datetime.date(1970, 1, 1) + datetime.timedelta(days=days)
    return day(date.year, date.month, date.day), rest // 1000, (rest % 1000) * 10 ** 6


def limit_case(name, old_ms, new_ms, window, limit, count):
    return Case(name, rec=(count,) + time_of(old_ms), now=time_of(new_ms), window=window, limit=limit)


NOW_MS = lock_millis(*NOW)


def limit_cases():
    cases = [Case("fresh record", now=NOW, window=60000, limit=3), Case("fresh record limit 0", window=60000, limit=0)]
    add = cases.append
    base = 1793458200000
    for name, old, new, window, limit, count in (
            ("same bucket", base + 1500, base + 1999, 1000, 10, 3), ("next bucket resets", base + 999, base + 1000, 1000, 10, 3), ("first ms of a bucket stays", base, base + 999, 1000, 10, 3),
            ("reset ignores the count", base, base + 1000, 1000, 1, 10 ** 12), ("skipped buckets reset", base, base + 86400000, 1000, 1, 7), ("clock back in bucket", base + 500, base + 100, 1000, 10, 3),
            ("clock back a bucket", base + 5000, base, 1000, 10, 3), ("limit equal", base, base + 1, 1000, 4, 3), ("limit one under", base, base + 1, 1000, 3, 3), ("limit zero", base, base + 1, 1000, 0, 0),
            ("limit zero after reset", base, base + 1000, 1000, 0, 0), ("count saturates", base, base + 1, 1000, TOP, TOP), ("saturated over", base, base + 1, 1000, TOP - 1, TOP), ("count one below saturation", base, base + 1, 1000, TOP - 1, TOP - 1),
            ("window one", base, base + 1, 1, 10, 9), ("window one same ms", base, base, 1, 10, 9), ("window just under 2^32", base, base + 1, 2 ** 32 - 1, 10, 2), ("window 2^32", base, base + 1, 2 ** 32, 10, 2),
            ("window above now", base, base + 1, 2 ** 45, 10, 2), ("both below 2^32", 1000, 3000, 2000, 10, 2), ("both below 2^32 same", 2000, 3999, 2000, 10, 2), ("old below 2^32", 1000, base, 2000, 10, 2),
            ("new below 2^32", base, 1000, 2000, 10, 2), ("low word of old set", 2 ** 32, 2 ** 32 + 1, 2000, 10, 2), ("year window", base, base + 31536000000, 31536000000, 10, 2)):
        add(limit_case(name, old, new, window, limit, count))
    add(Case("window zero faults", window=0))
    add(Case("old before 1970 floors", rec=(2, day(1960, 1, 1), 5, 6), now=time_of(500), window=1000))
    add(Case("new before 1970 floors", rec=(2,) + time_of(1500), now=(day(1960, 1, 1), 5, 6), window=1000))
    add(Case("nanoseconds floor", rec=(2, NOW[0], 7, 999999), now=(NOW[0], 7, 1000000), window=1))
    add(Case("leap second word", rec=(2, NOW[0], 59, 1999999999), now=(NOW[0], 60, 0), window=1000))
    add(Case("stored seconds differ", rec=(2, NOW[0], 7, 0), now=(NOW[0], 8, 0), window=1000))
    add(Case("stored day differs", rec=(2, day(2026, 10, 30), 7, 0), now=(day(2026, 10, 31), 7, 0), window=86400000))
    add(Case("leap year day", rec=(2, day(2024, 2, 29), 7, 0), now=(day(2024, 3, 1), 7, 0), window=86400000))
    add(Case("century year", rec=(2, day(2101, 1, 1), 0, 0), now=(day(2100, 12, 31), 0, 0), window=86400000))
    add(Case("century year old side", rec=(2, day(2101, 1, 1), 0, 0), now=(day(2101, 1, 2), 0, 0), window=86400000))
    add(Case("century year new side", rec=(2, day(2101, 1, 2), 0, 0), now=(day(2101, 1, 2), 0, 0), window=86400000))
    add(Case("stored nanoseconds exact ms", rec=(2, NOW[0], 7, 1000000), now=(NOW[0], 7, 1000000), window=1))
    return cases


def two_cases():
    cases = []
    new = time_of(5000000000000)
    same_bucket = time_of(5000000000000 - 1)
    for entry in sorted(TWO_ROLES):
        tag = "%x " % entry
        full = (9, ) + same_bucket
        for name, fields in (
                ("both pass", dict(now=new, rec1=full, rec2=full, l1=100, l2=100, w1p=60000, w2p=3600000)), ("first over", dict(now=new, rec1=(9,) + same_bucket, rec2=(1,) + same_bucket, l1=9, l2=100, w1p=60000, w2p=3600000)),
                ("second over", dict(now=new, rec1=(1,) + same_bucket, rec2=(9,) + same_bucket, l1=100, l2=9, w1p=60000, w2p=3600000)), ("both over", dict(now=new, rec1=full, rec2=full, l1=9, l2=9, w1p=60000, w2p=3600000, usage=3, total=4)),
                ("usage saturates", dict(usage=TOP, total=TOP)), ("usage one below", dict(usage=TOP - 1, total=TOP - 1)), ("distinct windows", dict(now=new, rec1=(1,) + time_of(5000000000000 - 60000), rec2=(1,) + time_of(5000000000000 - 1), w1p=60000, w2p=3600000, l1=1, l2=1)),
                ("first window zero", dict(w1p=0)), ("second window zero", dict(w2p=0)), ("first limit decides", dict(now=new, rec1=(4,) + same_bucket, rec2=(9,) + same_bucket, l1=5, l2=1, w1p=60000, w2p=3600000))):
            cases.append(Case(tag + name, entry=entry, **fields))
    return cases


def tier_cases():
    near = (5,) + NOW
    later = (NOW[0], NOW[1], NOW[2] + 1000000)
    cases = []
    for shape in ("leaf", "deep", "deep left", "miss", "empty", "short"):
        cases.append(Case("shape " + shape, entry=TIER, u_shape=shape, urec=near, grec=near, now=later))
    for name, fields in (("user limit equal", dict(urec=near, ul=6, grec=near, gl=6)), ("user over keeps global", dict(urec=near, ul=5, grec=near, gl=100)), ("global over", dict(urec=near, ul=100, grec=near, gl=5)),
                         ("user window zero", dict(uw=0)), ("global window zero", dict(gw=0, urec=near)), ("user reset", dict(urec=(99, day(2026, 10, 30), 0, 0), ul=1, grec=near)),
                         ("global reset", dict(urec=near, grec=(99, day(2026, 10, 30), 0, 0), gl=1)), ("different windows", dict(urec=near, uw=1000, ul=6, gw=7000, gl=100, grec=near)), ("insert first op", dict(u_shape="miss", ul=1)),
                         ("insert with limit zero", dict(u_shape="miss", ul=0)), ("insert in the 1970 bucket", dict(u_shape="miss", now=time_of(500))), ("date fails on insert", dict(u_shape="miss", epoch=0)), ("date fails on empty", dict(u_shape="empty", epoch=0))):
        fields.setdefault("now", later)
        cases.append(Case(name, entry=TIER, **fields))
    return cases


def filled(start, count, byte):
    return tuple(((start + index) & 63, byte, DECOY - index) for index in range(count))


def record_cases():
    h = ROUTE_HASH
    tail = (h & ~63) | 60
    plain = (("hit first", dict(table=((11, 0x5B, USER),))), ("hit after twin", dict(table=((11, 0x5B, DECOY), (14, 0x5B, USER)))), ("hit twin three ahead", dict(table=((11, 0x5B, DECOY), (12, 0x5B, DECOY - 1), (14, 0x5B, USER)))),
             ("hit second group", dict(table=filled(11, 16, 0x5C) + ((27, 0x5B, USER),))), ("hit third group", dict(table=filled(11, 48, 0x5C) + ((59, 0x5B, USER),))), ("hit wrapped", dict(hash=tail, table=((1, 0x5B, USER),))),
             ("hit on last key byte", dict(table=((11, 0x5B, USER ^ 1), (12, 0x5B, USER)))), ("hit on tail key byte", dict(table=((11, 0x5B, USER ^ (1 << 16)), (12, 0x5B, USER)))),
             ("miss empty table", dict()), ("miss after other", dict(table=((11, 0x5C, DECOY),))), ("miss twin", dict(table=((11, 0x5B, DECOY),))), ("miss tombstone", dict(table=((11, 0x80, None),))),
             ("miss full first group", dict(table=filled(11, 16, 0x5C))), ("miss full two groups", dict(table=filled(11, 32, 0x5C))), ("miss full three groups", dict(table=filled(11, 48, 0x5C))), ("miss wraps to slot 0", dict(hash=tail, table=filled(60, 4, 0x5C))), ("miss wraps past 0", dict(hash=tail, table=filled(60, 6, 0x5C))),
             ("grow on empty slot", dict(grow_left=0)), ("no grow on hit", dict(grow_left=0, table=((11, 0x5B, USER),))), ("grow with tombstone", dict(grow_left=0, table=((11, 0x80, None),))), ("date fails", dict(epoch=0)),
             ("items and left", dict(grow_left=1, items=0)))
    return [Case("%x %s" % (entry, name), entry=entry, **fields) for entry in (REC_A, REC_B) for name, fields in plain]


def core_cases():
    cases = []
    for sel in range(4):
        for a in (0, 1):
            for b in (0, 1):
                for c in (0, 1):
                    cases.append(Case("flags %d %d %d %d" % (sel, a, b, c), entry=CORE, sel=sel, op=sel, a=a, b=b, c=c))
    for shape in ("leaf", "deep", "deep left", "miss", "empty", "short"):
        cases.append(Case("user shape " + shape, entry=CORE, u_shape=shape))
    for name, fields in (("tag 3", dict(core_tag=3, core_byte=2)), ("tag 3 cap", dict(core_tag=3, core_byte=3)), ("tag 2", dict(core_tag=2)), ("tag 2 increased", dict(core_tag=2, inc=1, changed=TOP)), ("no increase", dict(inc=0, changed=TOP)),
                         ("room exact", dict(changed=900, bal=(1000, 100, 7))), ("room one short", dict(changed=901, bal=(1000, 100, 7))), ("no hold exact", dict(changed=1000, bal=(1000, 0, 7))), ("hold above total", dict(changed=1, bal=(5, 10, 7))),
                         ("sum wraps", dict(changed=TOP, bal=(TOP, 2, 7))), ("sum exact top", dict(changed=TOP - 2, bal=(TOP, 2, 7))), ("row miss", dict(bal_shape="miss", changed=1)), ("row deep", dict(bal_shape="deep", changed=10, bal=(10, 0, 7))), ("row deep short", dict(bal_shape="deep", changed=11, bal=(10, 0, 7))),
                         ("row empty", dict(bal_shape="empty", changed=1)), ("row empty zero change", dict(bal_shape="empty", changed=0)), ("row short zero change", dict(bal_shape="short", changed=0)), ("zero change passes", dict(changed=0, bal=(0, 0, 0))), ("row short", dict(bal_shape="short", changed=1)), ("flag set", dict(flag=1)), ("amount words", dict(w0=0, w1=77)),
                         ("avail word", dict(avail=TOP)), ("asset zero", dict(asset=0)), ("asset large", dict(asset=10 ** 12))):
        cases.append(Case(name, entry=CORE, **fields))
    return cases


def direct_cases():
    cases = []
    for entry in sorted(D_ROLES):
        tag = "%x " % entry
        for name, fields in (("ok", dict()), ("all no change", dict(w0=1, w1=0)), ("even word zero amount", dict(w0=2, w1=0)), ("odd word amount", dict(w0=3, w1=5)), ("high word bit", dict(w0=0x100, w1=0)), ("tag 3", dict(core_tag=3, core_byte=6)), ("tag 3 cap", dict(core_tag=3, core_byte=3)),
                             ("tag 2", dict(core_tag=2)), ("tag 2 zero", dict(core_tag=2, changed=0)), ("zero change", dict(changed=0)), ("apply refused", dict(apply=0x10)), ("apply refused 0", dict(apply=0)),
                             ("vault word 1", dict(vault_shape="leaf", vault_word=1)), ("vault word 0", dict(vault_shape="leaf", vault_word=0)), ("vault word 2", dict(vault_shape="leaf", vault_word=2)), ("vault word high", dict(vault_shape="leaf", vault_word=0x101)), ("vault deep", dict(vault_shape="deep", vault_word=1)), ("vault deep left", dict(vault_shape="deep left", vault_word=1)),
                             ("vault miss", dict(vault_shape="miss", vault_word=1)), ("vault short", dict(vault_shape="short", vault_word=1)), ("lock zero", dict(lock=0)), ("lock top", dict(lock=TOP)), ("lock top refused", dict(lock=TOP, core_tag=3, core_byte=1)),
                             ("op 0", dict(op=0, sel=0)), ("op 3", dict(op=3, sel=3)), ("op 2", dict(op=2, sel=2, avail=9)), ("selector differs", dict(op=1, sel=2, avail=TOP))):
            cases.append(Case(tag + name, entry=entry, **fields))
    return cases


def handler_cases():
    cases = []
    for entry in sorted(H_ROLES):
        tag = "%x " % entry
        for cls in range(6):
            for f0 in (0, 1):
                for f1 in (0, 1):
                    cases.append(Case(tag + "grid %d %d %d" % (cls, f0, f1), entry=entry, cls=cls, f5b0=f0, f5b1=f1))
        for op in range(4):
            for shape in ("absent", "leaf", "deep", "deep left", "miss", "short"):
                for asset in (0, 5):
                    for flag in (0, 1):
                        cases.append(Case(tag + "vault %d %s %d %d" % (op, shape, asset, flag), entry=entry, op=op, sel=op, vault_shape=shape, asset=asset, vault_flag=flag))
        old = (9,) + time_of(NOW_MS - 1)
        for name, fields in (("user tier over", dict(urec=(5,) + NOW, ul=5)), ("global tier over", dict(grec=(5,) + NOW, gl=5)), ("asset miss", dict(asset_shape="miss")), ("asset empty", dict(asset_shape="empty")), ("asset short", dict(asset_shape="short")), ("asset deep", dict(asset_shape="deep")),
                             ("tier before asset", dict(asset_shape="miss", urec=(5,) + NOW, ul=5)), ("class before tier", dict(cls=4, f5b0=0, urec=(5,) + NOW, ul=5)), ("direct refused", dict(d_tag=0xE2)), ("direct inner", dict(d_tag=0xE1)),
                             ("routed", dict(cls=3)), ("routed refused", dict(cls=3, d_tag=0xE2)), ("routed post fails", dict(cls=3, post_tag=0x15)), ("routed post fails with refusal", dict(cls=3, post_tag=0xE1, d_tag=0xE2)), ("routed over", dict(cls=3, rec1=old, rec2=old, l1=9, l2=9, w1p=60000, w2p=3600000, usage=2, total=3)),
                             ("routed one window left", dict(cls=3, rec1=old, rec2=old, l1=9, l2=100, w1p=60000, w2p=3600000)), ("routed saturated", dict(cls=3, usage=TOP, total=TOP)),
                             ("routed second window holds", dict(cls=3, rec1=old, rec2=(9,) + time_of(NOW_MS - 40), l1=9, l2=9, w1p=86400000, w2p=86400000)),
                             ("routed first window reset", dict(cls=3, rec1=(9,) + time_of(NOW_MS - 120000), rec2=old, l1=9, l2=9, w1p=60000, w2p=3600000)),
                             ("routed second window reset", dict(cls=3, rec1=old, rec2=(9,) + time_of(NOW_MS - 7200000), l1=9, l2=9, w1p=60000, w2p=3600000)), ("flag keeps class 3 direct", dict(cls=3, f5b1=1, usage=2, total=3)), ("op 0", dict(op=0, sel=0)), ("op 3 routed", dict(op=3, sel=3, cls=3)), ("special amount", dict(w0=0, w1=0)),
                             ("user shape miss", dict(u_shape="miss")), ("user shape empty", dict(u_shape="empty")), ("user deep", dict(u_shape="deep", urec=(5,) + NOW, ul=5)), ("date fails", dict(u_shape="miss", epoch=0))):
            cases.append(Case(tag + name, entry=entry, **fields))
    return cases


def named_cases():
    return limit_cases() + two_cases() + tier_cases() + record_cases() + core_cases() + direct_cases() + handler_cases()


def vector_cases(count):
    """Random limiter inputs with buckets that often sit next to each other, plus mixed handler inputs."""
    rng = lcg(0x1357)
    cases = []
    while len(cases) < count:
        pick = next(rng)
        window = (1 << (next(rng) % 46)) + next(rng) % 5000 + 1
        if pick % 4 == 0:
            new = next(rng) % (2 ** 44)
            old = max(0, new - next(rng) % (window * 2))
        elif pick % 4 == 1:
            new = next(rng) % (2 ** 33)
            old = next(rng) % (2 ** 33)
        else:
            new = 1700000000000 + next(rng) % (2 ** 37)
            old = new - new % window + next(rng) % window
        cases.append(Case("v%d" % len(cases), rec=(next(rng) >> (next(rng) % 64),) + time_of(old), now=time_of(new), window=window, limit=next(rng) >> (next(rng) % 64)))
        if len(cases) % 8 == 0:
            entry = sorted(H_ROLES)[next(rng) % 3]
            op = next(rng) % 4
            cases.append(Case("h%d" % len(cases), entry=entry, op=op, sel=op, cls=next(rng) % 5, f5b0=next(rng) % 2, f5b1=next(rng) % 2, vault_shape=("absent", "leaf", "miss")[next(rng) % 3], asset=next(rng) % 2 * 5, vault_flag=next(rng) % 2,
                              usage=next(rng) % 3, total=next(rng) % 3))
    return cases


def check_cases(harness, cases):
    outcomes = []
    for case in cases:
        before, got = harness.run(case)
        want = spec_run(case, before)
        if not same(got, want):
            raise EvidenceError("case disagrees with the rule list: %s" % case.name + diff_text(got, want))
        outcomes.append((got, want[5]))
    return outcomes


def diff_text(got, want):
    if got[0] != want[0]:
        return " form %r %r" % (got[:2] if got[0] != "run" and got[0] != "value" else got[0], want[:2] if want[0] != "run" and want[0] != "value" else want[0])
    if got[1] != want[1]:
        if isinstance(got[1], bytes):
            at = next(index for index in range(len(got[1])) if got[1][index] != want[1][index])
            return " heap +%#x got %s want %s" % (at, got[1][at:at + 16].hex(), want[1][at:at + 16].hex())
        return " value %r %r" % (got[1], want[1])
    if got[3] != want[3]:
        return " events %r %r" % (got[3], want[3])
    return " output %r %r" % (got[4], want[4])


def text_at(image, arm):
    """The string a text Display arm hands to write_str: `lea text,%rsi` then `mov $len,%edx`."""
    start = image.offset(arm)
    data = bytes(image.blob[start:start + 40])
    at = data.find(b"\x48\x8d\x35")
    if at < 0 or data[at + 7] != 0xBA:
        raise EvidenceError("no text at %#x" % arm)
    target = arm + at + 7 + struct.unpack_from("<i", data, at + 3)[0]
    size = struct.unpack_from("<I", data, at + 8)[0]
    return bytes(image.blob[image.offset(target):image.offset(target) + size]).decode()


def arm_of(image, table, index):
    return table + struct.unpack_from("<i", image.blob, image.offset(table) + 4 * index)[0]


def text_rows(image):
    rows = []
    for tag in (0x15, 0x170, 0x173, 0xE2, 0xEA, 0x13F, 0x15C):
        rows.append(("tag", "%#x" % tag, text_at(image, arm_of(image, TAG_TEXT_TABLE, tag))))
    for code in (0, 1, 2, 3, 4, 6, 7, 8, 9):
        rows.append(("inner", code, text_at(image, arm_of(image, INNER_TABLE, code))))
    rows.append(("inner", 10, text_at(image, INNER_ARM_10)))
    return rows


def table_rows(image):
    rows = []
    for name, table in (("op table in the handler", OP_TABLE), ("selector table", SELECT_TABLE), ("closure table", CLOSURE_TABLE)):
        for index in range(4):
            rows.append((name, index, "%#x" % arm_of(image, table, index)))
    return rows


STRING_RUNS = (b"dexAbstractionunifiedAccountportfolioMargin", b"userDexAbstractionborrowLendsendToEvmWithData", b"struct variant SetBole::RateLimit with 7 elements", b"ubglnubglmubulnubulmusMpmp")


def string_rows(image):
    rows = []
    for run in STRING_RUNS:
        at = image.blob.find(run)
        if at < 0:
            raise EvidenceError("string missing")
        rows.append(("%#x" % at, run.decode()))
    return rows


VOTE_FUNCTIONS = (0x2355F40, 0x4CAA870, 0x4CB3200)
PARAMS = {0x4E8: "abstraction first window ms", 0x4F0: "abstraction first limit", 0x4F8: "abstraction second window ms", 0x500: "abstraction second limit", 0x508: "global window ms", 0x510: "global limit", 0x518: "user window ms", 0x520: "user limit"}


def vote_rows(image):
    """Stores to a parameter offset in each dispatcher, by bytes: REX.W 89 modrm(mod 2, no SIB) disp32."""
    rows = []
    for function in VOTE_FUNCTIONS:
        start, end = image.exact_fde(function)
        data = bytes(image.blob[image.offset(start):image.offset(end - 1) + 1])
        for match in re.finditer(rb"[\x48\x49\x4c\x4d]\x89([\x80-\xbf])(....)", data, re.S):
            disp = struct.unpack("<i", match[2])[0]
            if disp in PARAMS and match[1][0] & 7 != 4:
                rows.append(("%#x" % function, "%#x" % (start + match.start()), "%#x" % disp, PARAMS[disp]))
    return rows


def holder_rows(image):
    relative = image.relative()
    wanted = set(TARGETS)
    slots = collections.defaultdict(list)
    for slot, value in relative.items():
        if value in wanted:
            slots[value].append(slot)
    held = {slot: target for target, items in slots.items() for slot in items}
    va, text = image.text_bytes()
    direct = collections.defaultdict(list)
    for match in re.finditer(rb"[\xe8\xe9]", text):
        if match.start() + 5 > len(text):
            break
        target = va + match.start() + 5 + struct.unpack_from("<i", text, match.start() + 1)[0]
        if target in wanted:
            direct[target].append(va + match.start())
    indirect = collections.defaultdict(list)
    for match in re.finditer(rb"\xff\x15", text):
        if match.start() + 6 > len(text):
            break
        slot = va + match.start() + 6 + struct.unpack_from("<i", text, match.start() + 2)[0]
        if slot in held:
            indirect[held[slot]].append(va + match.start())
    for match in re.finditer(rb"[\x48\x4c]\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", text):
        if match.start() + 7 > len(text):
            break
        slot = va + match.start() + 7 + struct.unpack_from("<i", text, match.start() + 3)[0]
        if slot in held:
            indirect[held[slot]].append(va + match.start())
    rows = []
    for target in TARGETS:
        rows.append(("%#x" % target, NAMES[target], " ".join("%#x" % s for s in sorted(slots[target])), len(direct[target]), " ".join("%#x" % s for s in sorted(direct[target])[:12]), len(indirect[target]), " ".join("%#x" % s for s in sorted(indirect[target])[:12])))
    return rows


def route_rows(harness):
    """Which path each class and flag pair takes in the first handler copy, read from the run's events."""
    rows = []
    for cls in range(5):
        for f0 in (0, 1):
            for f1 in (0, 1):
                case = Case("route", entry=0x2764D60, cls=cls, f5b0=f0, f5b1=f1)
                _, got = harness.run(case)
                names = [event[0] for event in got[3]]
                route = "refused 0x173" if "direct" not in names else "routed" if "pre" in names else "direct"
                rows.append((cls, f0, f1, route, " ".join(names)))
    return rows


def limiter_rows(harness):
    rows = []
    base = 1793458200000
    for name, old, new, window, limit, count in (("same bucket", base + 1500, base + 1999, 1000, 10, 3), ("edge of next bucket", base + 999, base + 1000, 1000, 10, 3), ("refused still counts", base + 1, base + 2, 1000, 3, 3), ("refused again", base + 2, base + 3, 1000, 3, 4),
                                                 ("reset passes a low limit", base, base + 1000, 1000, 1, 10 ** 12), ("limit 0 refuses a reset", base, base + 1000, 1000, 0, 7), ("clock back keeps counting", base + 5000, base, 1000, 10, 3), ("saturated", base, base + 1, 1000, TOP, TOP)):
        case = limit_case(name, old, new, window, limit, count)
        _, got = harness.run(case)
        after = int.from_bytes(got[1][LREC - HEAP_BASE:LREC - HEAP_BASE + 8], "little")
        rows.append((name, old, new, window, limit, count, after, got[4]))
    return rows


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
            if not same(got, spec_run(case, before)):
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, Panicked):
            return case
    return None


SELF_COPY = "the second copy puts bytes back over themselves; the first copy did not touch the source, so one byte less changes nothing"
DEAD_CLASS = "this row runs only for class 3, since the first gate stops the class 4 path, so 4 and 5 compare the same"
ALL_BYTES_SAME = "shuffle of a value whose bytes are all equal"
UNREAD_WORD = "the hit form of the probe result: this third word is read only by the insert form"
NEVER_NEGATIVE = "fixes up a negative quotient; y is never negative after the 400 year shift"
ZERO_COUNT = "a new record has count 0, so a reset and a plus one both give 1, and the time word is overwritten by the same call"
EXPECTED_SURVIVORS = {}
for _rows, _kind, _text in (
        ((0x2732DA3, 0x4D44DA3, 0x4D4A1A3), "immediate", SELF_COPY),
        ((0x276515B, 0x27651B6, 0x4D95E87, 0x4D95ED6, 0x4D96457, 0x4D964A6), "immediate", DEAD_CLASS),
        ((0x27C4B7B, 0x47D7592), "immediate", ALL_BYTES_SAME),
        ((0x27C4C25,), "displacement", UNREAD_WORD),
        ((0x37D9F9A, 0x37DA038), "immediate", NEVER_NEGATIVE),
        ((0x373CB26,), "immediate", ZERO_COUNT)):
    for _row in _rows:
        EXPECTED_SURVIVORS[_row, _kind] = _text


def run_mutants(image, table, seen, cases):
    results = []
    control = Harness(image)
    control.machine.step_limit = MUTANT_STEP_LIMIT
    if first_failure(control, cases) is not None:
        raise EvidenceError("an unedited image fails under the mutant step limit")
    groups = collections.defaultdict(list)
    for case in cases:
        groups[case.entry].append(case)
    for entry, rows in list(groups.items()):
        if entry in H_ROLES:
            rows.sort(key=lambda case: 0 if case.vault_shape == "absent" else 1)
    groups[PROBE_A] = groups[REC_A]
    extra = [case for case in vector_cases(120)]
    for target in TARGETS:
        chosen = groups[target] + [case for case in extra if case.entry == target]
        if target == TIER:
            chosen = chosen + groups[0x2764D60][:40]
        for va, kind, patch in edits_for(image, table[target], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = MUTANT_STEP_LIMIT
            hit = first_failure(harness, chosen)
            if hit is not None:
                results.append((va, kind, "killed", hit.name))
            else:
                results.append((va, kind, "survived", EXPECTED_SURVIVORS.get((va, kind), "UNEXPLAINED")))
    return results



def analyse(image, mutate=True, vectors=1500):
    harness = Harness(image)
    cases = named_cases()
    outcomes = check_cases(harness, cases)
    vector = vector_cases(vectors)
    check_cases(harness, vector)
    seen = set(harness.machine.seen)
    table = {target: rows_of(image, target) for target in TARGETS}
    unreached = {target: [row.va for row in table[target] if row.va not in seen and row.op not in ("int3", "nop")] for target in TARGETS}
    result = dict(table=table, cases=cases, outcomes=outcomes, vector_count=len(vector), unreached=unreached, texts=text_rows(image), tables=table_rows(image), strings=string_rows(image), votes=vote_rows(image), holders=holder_rows(image),
                  routes=route_rows(harness), limiter=limiter_rows(harness))
    if mutate:
        result["mutations"] = run_mutants(image, table, seen, cases)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def describe(case, outcome):
    got, label = outcome
    return "%#x" % case.entry, case.name, label, hashlib.sha256(repr((got[0], got[1], got[3], got[4])).encode()).hexdigest()[:16], len(got[3])


def render(result):
    files = {}

    def tsv(name, header, rows):
        lines = ["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]
        files[name] = "\n".join(lines) + "\n"

    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"), [("%#x" % target, "%#x" % row.va, row.size, row.data.hex(), row.op) for target in TARGETS for row in result["table"][target]])
    tsv("texts.tsv", ("kind", "code", "text"), result["texts"])
    tsv("jump-tables.tsv", ("table", "index", "arm"), result["tables"])
    tsv("strings.tsv", ("file_offset", "text"), result["strings"])
    tsv("vote-stores.tsv", ("dispatcher", "store_address", "offset", "reading"), result["votes"])
    tsv("holders.tsv", ("function", "name", "relative_slots", "direct_count", "direct_sites_first_12", "slot_count", "slot_sites_first_12"), result["holders"])
    tsv("class-routes.tsv", ("class_byte", "flag_5b0", "flag_5b1", "route", "edges"), result["routes"])
    tsv("limiter-samples.tsv", ("scenario", "stored_ms", "now_ms", "window", "limit", "count_before", "count_after", "passed"), result["limiter"])
    tsv("outcomes.tsv", ("entry", "case", "result", "digest", "events"), [describe(case, outcome) for case, outcome in zip(result["cases"], result["outcomes"])])
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

